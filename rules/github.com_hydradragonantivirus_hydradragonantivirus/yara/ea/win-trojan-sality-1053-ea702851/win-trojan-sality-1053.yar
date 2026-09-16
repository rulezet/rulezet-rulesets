rule Win_Trojan_Sality_1053
{
strings:
	$a0 = { 8a440500[0-2]3007[0-4]80e901[0-2]5e4e[0-4]0f84 }


condition:
	$a0
}