rule Win_Trojan_Demon_6
{
strings:
	$a0 = { b42acd213c027404b44ccd21c606be01 }


condition:
	$a0
}