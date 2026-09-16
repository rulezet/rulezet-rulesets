rule Win_Trojan_N_45
{
strings:
	$a0 = { 0300037c01bb0700b40bcd10b93c008db52401acf6d0b40ecd10e2f7b300b40bcd10c3f8aa9196899a8d8c9e93dfaf }


condition:
	$a0
}