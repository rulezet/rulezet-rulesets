rule Win_Trojan_TheRat_1
{
strings:
	$a0 = { e833ffb80042ba8000e837ffb98001ba100a }


condition:
	$a0
}