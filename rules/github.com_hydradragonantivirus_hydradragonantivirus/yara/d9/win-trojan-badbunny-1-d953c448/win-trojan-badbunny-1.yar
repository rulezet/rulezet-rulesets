rule Win_Trojan_Badbunny_1
{
strings:
	$a0 = { 6966286d61726b6572213d222f2f2062616462756e6e792229 }


condition:
	$a0
}