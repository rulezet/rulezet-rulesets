rule GSM_table_gsm_NRFAC__16_big_16_
{
strings:
	$a0 = { 71c866675d1855564ec5492544444000 }

condition:
	$a0
}