rule Win_Trojan_Badguy_2
{
strings:
	$a0 = { 01b90b1190b44ecd21907302eb25 }


condition:
	$a0
}