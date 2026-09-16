rule Win_Trojan_Small_4413
{
strings:
	$a0 = { 565753e9080000008d0418e9a9000000e9 }


condition:
	$a0
}