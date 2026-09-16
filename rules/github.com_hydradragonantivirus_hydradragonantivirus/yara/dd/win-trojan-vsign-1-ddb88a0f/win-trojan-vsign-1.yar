rule Win_Trojan_VSign_1
{
strings:
	$a0 = { 8ed88ec08ed048488be0fb32e4cd1372fab80202bb007eb90200ba0001cd1372eae99901 }


condition:
	$a0
}