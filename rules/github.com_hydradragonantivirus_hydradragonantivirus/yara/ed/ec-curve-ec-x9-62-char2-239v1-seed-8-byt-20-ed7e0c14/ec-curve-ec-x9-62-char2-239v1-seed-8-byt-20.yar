rule EC_curve__EC_X9_62_CHAR2_239V1_SEED__8_byt_20_
{
strings:
	$a0 = { d34b9a4d696e676875615175ca71b920bfefb05d }

condition:
	$a0
}