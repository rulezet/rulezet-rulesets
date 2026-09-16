rule EC_curve__EC_X9_62_CHAR2_359V1_SEED__8_byt_20_
{
strings:
	$a0 = { 2b354920b724d696e67687561517585ba1332dc6 }

condition:
	$a0
}