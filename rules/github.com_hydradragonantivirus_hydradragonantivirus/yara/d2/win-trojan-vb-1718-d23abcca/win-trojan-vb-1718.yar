rule Win_Trojan_VB_1718
{
strings:
	$a0 = { 61726f68756d6963000001000200d4334000 }


condition:
	$a0
}