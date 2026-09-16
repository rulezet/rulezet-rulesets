rule Win_Trojan_Gerg_2
{
strings:
	$a0 = { 7320e80800b44fcd21725473deb43ecd }


condition:
	$a0
}