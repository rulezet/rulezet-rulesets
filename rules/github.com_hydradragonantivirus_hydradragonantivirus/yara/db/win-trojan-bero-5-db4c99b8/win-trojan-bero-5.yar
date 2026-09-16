rule Win_Trojan_Bero_5
{
strings:
	$a0 = { 33c905000140054e0040cd21501e51591f58b42080c41580c40afec4b91a00baaa02cd2152 }


condition:
	$a0
}