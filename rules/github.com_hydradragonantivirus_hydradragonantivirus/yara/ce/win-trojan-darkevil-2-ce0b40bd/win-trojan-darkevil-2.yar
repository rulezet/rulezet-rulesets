rule Win_Trojan_DarkEvil_2
{
strings:
	$a0 = { 3de89eff720d0a8bd8e82e00b43ee8 }


condition:
	$a0
}