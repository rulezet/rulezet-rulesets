rule Win_Trojan_MrTwister_3
{
strings:
	$a0 = { 01b43bcd21e813000ee84b00ba8b01b43bcd21e805000ee83d00c30e1fbacc01b44ecd217230ba9e00b43db00290 }


condition:
	$a0
}