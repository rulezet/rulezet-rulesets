rule Win_Trojan_Itty_2
{
strings:
	$a0 = { ba9e00cd2193b43fb90200ba7f02cd21813e7f028bf69c }


condition:
	$a0
}