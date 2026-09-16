rule Win_Trojan_Frz_1
{
strings:
	$a0 = { 5e81ee75000e1ffa2e89a40a00bc970003e68bde81c3b300b9 }


condition:
	$a0
}