rule Win_Trojan_CyberTech_7
{
strings:
	$a0 = { 81ed0701502e8b86e0012e8b9ee2012ea300022e891e0202b41aba00fdcd21b44e8d96da0133c9cd217303e97c00b8 }


condition:
	$a0
}