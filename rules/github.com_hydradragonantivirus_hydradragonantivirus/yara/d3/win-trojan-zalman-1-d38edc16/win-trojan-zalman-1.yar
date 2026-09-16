rule Win_Trojan_Zalman_1
{
strings:
	$a0 = { 626f21776a7376542e9a000081005589e5b800069a7c02 }


condition:
	$a0
}