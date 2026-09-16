rule GSM_table_gsm_B__16_big_16_
{
strings:
	$a0 = { 000000000800F600005EF900FEABFB88 }

condition:
	$a0
}