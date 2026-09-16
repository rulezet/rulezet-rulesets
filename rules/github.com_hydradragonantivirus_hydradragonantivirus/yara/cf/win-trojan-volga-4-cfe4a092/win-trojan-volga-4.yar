rule Win_Trojan_Volga_4
{
strings:
	$a0 = { be007c33fffa8ed78be6fbea2901c007 }


condition:
	$a0
}