rule Win_Trojan_Kurt_2
{
strings:
	$a0 = { cd21b43ecd21b4098d960f03cd21b400cd162e8b9e840380e3fb6802fa586845595acd136800 }


condition:
	$a0
}