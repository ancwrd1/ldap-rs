pub use bytes::Bytes;
use pest::{
    iterators::{Pair, Pairs},
    Parser,
};
use pest_derive::Parser;
use rasn::prelude::*;
use rasn_ldap::{AttributeValueAssertion, Filter, MatchingRuleAssertion, SubstringChoice, SubstringFilter};

use crate::error::Error;

type RulePair<'a> = Pair<'a, Rule>;
type RulePairs<'a> = Pairs<'a, Rule>;

#[derive(Parser)]
#[grammar = "filter.pest"]
pub(crate) struct FilterParser;

pub(crate) fn filter_to_ldap<S: AsRef<str>>(filter: S) -> Result<Filter, Error> {
    let mut parsed = FilterParser::parse(Rule::rfc2254, filter.as_ref())?;
    Ok(pair_to_ldap(parsed.next().expect("No top level rule")))
}

fn as_bytes(pair: &RulePair) -> Bytes {
    pair.as_str().to_owned().into()
}

fn as_inner(pair: RulePair) -> RulePair {
    pair.into_inner().next().expect("No inner rule")
}

fn pair_to_ldap(pair: RulePair) -> Filter {
    match pair.as_rule() {
        Rule::and => Filter::And(pairs_to_set(pair.into_inner())),
        Rule::or => Filter::Or(pairs_to_set(pair.into_inner())),
        Rule::not => Filter::Not(Box::new(pair_to_ldap(as_inner(pair)))),
        Rule::simple => simple_to_ldap(pair.into_inner()),
        Rule::present => Filter::Present(as_bytes(&as_inner(pair))),
        Rule::substring => substring_to_ldap(pair.into_inner()),
        Rule::extensible => extensible_to_ldap(pair.into_inner()),
        _ => panic!("Unexpected rule"),
    }
}

fn extensible_to_ldap(pairs: RulePairs) -> Filter {
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

fn simple_to_ldap(pairs: RulePairs) -> Filter {
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
fn pairs_to_set(pairs: RulePairs) -> SetOf<Filter> {
    pairs.map(pair_to_ldap).collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn test_parser() {
        let test_filters = vec![
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
            assert_eq!(filter_to_ldap(f.0).unwrap(), f.1);
        });
    }
}
