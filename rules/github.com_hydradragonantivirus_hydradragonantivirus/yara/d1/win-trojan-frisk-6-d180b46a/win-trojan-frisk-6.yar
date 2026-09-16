rule Win_Trojan_Frisk_6
{
strings:
	$a0 = { 5e619d9c60565755061eb80043cd212e890e9303b8014333c9cd21b8023dcd218bd8b80057cd21 }


condition:
	$a0
}