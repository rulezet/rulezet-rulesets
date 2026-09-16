rule EC_curve__EC_NIST_PRIME_521_SEED__8_byt_20_
{
strings:
	$a0 = { d09e8800291cb85396cc6717393284aaa0da64ba }

condition:
	$a0
}