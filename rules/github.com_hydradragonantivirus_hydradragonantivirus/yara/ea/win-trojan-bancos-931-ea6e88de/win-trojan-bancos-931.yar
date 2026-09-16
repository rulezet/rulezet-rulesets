rule Win_Trojan_Bancos_931
{
strings:
	$a0 = { 63befd5c1bdb1d2c132ae1e98a0ffbd9f6f36cb36ac4338e46c45025cdf7d320d2ca4351f3cdf18cd0dc8335c196fa77d5c49514510ec1c1e3b718cf1de531986ea1075dc40eaacf82502e85eb25 }


condition:
	$a0
}