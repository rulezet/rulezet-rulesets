rule Win_Trojan_U_115
{
strings:
	$a0 = { 2dfeaffeaf5281ec181100005383c4fceb6d8d44241850ffb42430110000e89c }


condition:
	$a0
}