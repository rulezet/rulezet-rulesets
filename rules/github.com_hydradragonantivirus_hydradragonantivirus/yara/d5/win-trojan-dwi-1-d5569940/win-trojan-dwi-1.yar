rule Win_Trojan_DWI_1
{
strings:
	$a0 = { 01b90402ba00002e31172ed10f4343e2f6 }


condition:
	$a0
}