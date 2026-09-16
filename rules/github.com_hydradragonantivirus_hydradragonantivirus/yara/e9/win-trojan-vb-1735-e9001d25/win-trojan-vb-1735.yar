rule Win_Trojan_VB_1735
{
strings:
	$a0 = { 42000650830145787465726d696e }


condition:
	$a0
}