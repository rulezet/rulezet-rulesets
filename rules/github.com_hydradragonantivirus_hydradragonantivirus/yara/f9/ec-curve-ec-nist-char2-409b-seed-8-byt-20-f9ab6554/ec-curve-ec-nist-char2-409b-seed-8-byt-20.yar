rule EC_curve__EC_NIST_CHAR2_409B_SEED__8_byt_20_
{
strings:
	$a0 = { 4099b5a457f9d69f79213d094c4bcd4d4262210b }

condition:
	$a0
}