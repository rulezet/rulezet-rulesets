rule Win_Trojan_B_7
{
strings:
	$a0 = { c08ed8be137cb9a5018a3eba7d303c46e2fb }


condition:
	$a0
}