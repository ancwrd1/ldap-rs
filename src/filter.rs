use std::borrow::Cow;

use bytes::Bytes;
use once_cell::sync::Lazy;
use pest::{
    iterators::{Pair, Pairs},
    Parser,
};
use pest_derive::Parser;
use rasn::prelude::*;
use rasn_ldap::{AttributeValueAssertion, Filter, MatchingRuleAssertion, SubstringChoice, SubstringFilter};
use regex::{Captures, Regex};

use crate::error::Error;

type RulePair<'a> = Pair<'a, Rule>;
type RulePairs<'a> = Pairs<'a, Rule>;

fn unescape(s: &str) -> Cow<str> {
    static HEX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"\\([\da-fA-F]{2})"#).unwrap());

    HEX_RE.replace_all(s, |caps: &Captures| {
        // unwrap is justified here by the regex expression
        (u8::from_str_radix(&caps[1], 16).unwrap() as char).to_string()
    })
}

#[derive(Parser)]
#[grammar = "filter.pest"]
pub(crate) struct FilterParser;

pub(crate) fn parse_filter<S: AsRef<str>>(filter: S) -> Result<Filter, Error> {
    let unescaped = unescape(filter.as_ref());
    let mut parsed = FilterParser::parse(Rule::rfc2254, &unescaped)?;
    Ok(parse_rule(parsed.next().expect("No top level rule")))
}

fn as_bytes(pair: &RulePair) -> Bytes {
    pair.as_str().as_bytes().to_vec().into()
}

fn as_inner(pair: RulePair) -> RulePair {
    pair.into_inner().next().expect("No inner rule")
}

fn parse_rule(pair: RulePair) -> Filter {
    match pair.as_rule() {
        Rule::and => Filter::And(parse_set(pair.into_inner())),
        Rule::or => Filter::Or(parse_set(pair.into_inner())),
        Rule::not => Filter::Not(Box::new(parse_rule(as_inner(pair)))),
        Rule::simple => parse_simple(pair.into_inner()),
        Rule::present => Filter::Present(as_bytes(&as_inner(pair))),
        Rule::substring => substring_to_ldap(pair.into_inner()),
        Rule::extensible => parse_extensible(pair.into_inner()),
        _ => panic!("Unexpected rule"),
    }
}

fn parse_extensible(pairs: RulePairs) -> Filter {
    let mut assertion = MatchingRuleAssertion::new(None, None, Bytes::default(), false);
    for pair in pairs {
        match pair.as_rule() {
            Rule::ruleid => assertion.matching_rule = Some(as_bytes(&pair)),
            Rule::ident => assertion.r#type = Some(as_bytes(&pair)),
            Rule::string => assertion.match_value = as_bytes(&pair),
            Rule::dnattr => assertion.dn_attributes = true,
            _ => panic!("Unexpected rule"),
        }
    }
    Filter::ExtensibleMatch(assertion)
}

fn substring_to_ldap(mut pairs: RulePairs) -> Filter {
    let attr = as_bytes(&pairs.next().unwrap());
    let choices = pairs
        .map(|pair| match pair.as_rule() {
            Rule::initial => SubstringChoice::Initial(as_bytes(&pair)),
            Rule::any => SubstringChoice::Any(as_bytes(&pair)),
            Rule::final_ => SubstringChoice::Final(as_bytes(&pair)),
            _ => panic!("Unexpected rule"),
        })
        .collect();
    Filter::Substrings(SubstringFilter::new(attr, choices))
}

fn parse_simple(pairs: RulePairs) -> Filter {
    let pairs = pairs.collect::<Vec<_>>();
    let assertion = AttributeValueAssertion::new(as_bytes(&pairs[0]), as_bytes(&pairs[2]));
    match pairs[1].as_rule() {
        Rule::equal => Filter::EqualityMatch(assertion),
        Rule::approx => Filter::ApproxMatch(assertion),
        Rule::greater => Filter::GreaterOrEqual(assertion),
        Rule::less => Filter::LessOrEqual(assertion),
        _ => panic!("Unexpected rule"),
    }
}

#[allow(clippy::mutable_key_type)]
fn parse_set(pairs: RulePairs) -> SetOf<Filter> {
    pairs.map(parse_rule).collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn test_parser() {
        let test_filters = vec![
            (
                r#"(cn=Babs Jensen\30\30\01)"#,
                Filter::EqualityMatch(AttributeValueAssertion::new(
                    "cn".into(),
                    b"Babs Jensen00\x01".to_vec().into(),
                )),
            ),
            (
                "(cn=Babs Jensen)",
                Filter::EqualityMatch(AttributeValueAssertion::new("cn".into(), "Babs Jensen".into())),
            ),
            ("(cn=*)", Filter::Present("cn".into())),
            (
                "(!(cn=Tim Howes))",
                Filter::Not(Box::new(Filter::EqualityMatch(AttributeValueAssertion::new(
                    "cn".into(),
                    "Tim Howes".into(),
                )))),
            ),
            (
                "(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))",
                Filter::And(BTreeSet::from([
                    Filter::EqualityMatch(AttributeValueAssertion::new("objectClass".into(), "Person".into())),
                    Filter::Or(BTreeSet::from([
                        Filter::EqualityMatch(AttributeValueAssertion::new("sn".into(), "Jensen".into())),
                        Filter::Substrings(SubstringFilter::new(
                            b"cn".to_vec().into(),
                            vec![SubstringChoice::Initial("Babs J".into())],
                        )),
                    ])),
                ])),
            ),
            (
                "(o=univ*of*mich*end)",
                Filter::Substrings(SubstringFilter::new(
                    b"o".to_vec().into(),
                    vec![
                        SubstringChoice::Initial("univ".into()),
                        SubstringChoice::Any("of".into()),
                        SubstringChoice::Any("mich".into()),
                        SubstringChoice::Final("end".into()),
                    ],
                )),
            ),
            (
                "(cn:1.2.3.4.5:=Fred Flintstone)",
                Filter::ExtensibleMatch(MatchingRuleAssertion::new(
                    Some("1.2.3.4.5".into()),
                    Some("cn".into()),
                    "Fred Flintstone".into(),
                    false,
                )),
            ),
            (
                "(sn:dn:2.4.6.8.10:=Barney Rubble)",
                Filter::ExtensibleMatch(MatchingRuleAssertion::new(
                    Some("2.4.6.8.10".into()),
                    Some("sn".into()),
                    "Barney Rubble".into(),
                    true,
                )),
            ),
            (
                "(o:dn:=Ace Industry)",
                Filter::ExtensibleMatch(MatchingRuleAssertion::new(
                    None,
                    Some("o".into()),
                    "Ace Industry".into(),
                    true,
                )),
            ),
            (
                "(:dn:2.4.6.8.10:=Dino)",
                Filter::ExtensibleMatch(MatchingRuleAssertion::new(
                    Some("2.4.6.8.10".into()),
                    None,
                    "Dino".into(),
                    true,
                )),
            ),
            (
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))",
                Filter::Not(Box::new(Filter::ExtensibleMatch(MatchingRuleAssertion::new(
                    Some("1.2.840.113556.1.4.803".into()),
                    Some("userAccountControl".into()),
                    "2".into(),
                    false,
                )))),
            ),
        ];

        test_filters.iter().for_each(|f| {
            assert_eq!(parse_filter(f.0).unwrap(), f.1);
        });
    }

    #[test]
    fn test_unescape() {
        let hex = r#"hello\20\77\6f\72\6c\64\00\01"#;
        let decoded = unescape(hex);
        assert_eq!(decoded, "hello world\u{0000}\u{0001}");
    }

    #[test]
    fn test_unescape_bad_pattern() {
        let hex = r#"hello\\gg"#;
        let decoded = unescape(hex);
        assert_eq!(decoded, "hello\\\\gg");
    }
}
