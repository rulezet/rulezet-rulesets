rule Win_Trojan_Small_4435
{
strings:
	$a0 = { 81c8????4000505068ccf61af1e860000000e875 }


condition:
	$a0
}