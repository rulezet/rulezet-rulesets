rule EC_curve__EC_NIST_CHAR2_233B_SEED__8_byt_20_
{
strings:
	$a0 = { 74d59ff07f6b413d0ea14b344b20a2db049b50c3 }

condition:
	$a0
}