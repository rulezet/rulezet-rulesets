rule GSM_A38_table_4__8_byt_32_
{
strings:
	$a0 = { 0f0c0a04010e0b0705000e0701020d080a03040906000302050608090b0d0f0c }

condition:
	$a0
}