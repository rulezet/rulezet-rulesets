rule Win_Trojan_Ieronim_11
{
strings:
	$a0 = { 0603008ec033ff0e1fb95802f3a433c08ed88b1e84 }


condition:
	$a0
}