rule Win_Trojan_DIR_II_1
{
strings:
	$a0 = { 01b9f50380370043e2fa }


condition:
	$a0
}