rule Win_Trojan_Bestwish_1
{
strings:
	$a0 = { b4ffcd2180fcfa7503eb61901e31c08e }


condition:
	$a0
}