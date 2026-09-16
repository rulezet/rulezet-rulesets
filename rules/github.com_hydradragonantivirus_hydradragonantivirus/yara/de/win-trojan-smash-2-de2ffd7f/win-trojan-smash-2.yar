rule Win_Trojan_Smash_2
{
strings:
	$a0 = { 01b44ecd217213b43c33c9ba9401cd217208b441cd21b44febe9b41a8e1ea1018b16a301cd21 }


condition:
	$a0
}