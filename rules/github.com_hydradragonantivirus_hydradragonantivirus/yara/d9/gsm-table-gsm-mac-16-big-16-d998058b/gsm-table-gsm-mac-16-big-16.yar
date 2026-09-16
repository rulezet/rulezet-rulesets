rule GSM_table_gsm_MAC__16_big_16_
{
strings:
	$a0 = { 001f001f000f000f0007000700030003 }

condition:
	$a0
}