rule Win_Trojan_Milana_1
{
strings:
	$a0 = { 8b26060033db53ffe0ba1000f7e2c3558becff7606 }


condition:
	$a0
}