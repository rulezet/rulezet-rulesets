rule Win_Trojan_VGEN_534
{
strings:
	$a0 = { ff0020c606f80000c706fd00ffff813e0000cd206a001f7568b4fbcd137315e8ef000e0e07e8 }


condition:
	$a0
}