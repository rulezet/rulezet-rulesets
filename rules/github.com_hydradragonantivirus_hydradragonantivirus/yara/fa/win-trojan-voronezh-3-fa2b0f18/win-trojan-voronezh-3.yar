rule Win_Trojan_Voronezh_3
{
strings:
	$a0 = { a406f3a48bd0eb74909cfb80fcab75 }


condition:
	$a0
}