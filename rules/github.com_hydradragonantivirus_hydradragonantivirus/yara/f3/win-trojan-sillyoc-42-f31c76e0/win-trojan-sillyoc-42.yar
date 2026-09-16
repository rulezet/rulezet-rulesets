rule Win_Trojan_SillyOC_42
{
strings:
	$a0 = { 8fff85bc74b097409f416dbb9912461943a31c04c3a599626b5a034521d2 }


condition:
	$a0
}