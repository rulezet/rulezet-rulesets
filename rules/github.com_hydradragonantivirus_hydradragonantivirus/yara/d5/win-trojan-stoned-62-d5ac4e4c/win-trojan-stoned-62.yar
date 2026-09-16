rule Win_Trojan_Stoned_62
{
strings:
	$a0 = { 01034126c606057e02cd1326803e017c3475182e8c0ee1002ec706df00e300 }


condition:
	$a0
}