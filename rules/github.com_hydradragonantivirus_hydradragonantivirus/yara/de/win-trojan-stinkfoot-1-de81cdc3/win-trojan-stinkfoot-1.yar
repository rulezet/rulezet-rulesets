rule Win_Trojan_Stinkfoot_1
{
strings:
	$a0 = { 59ba0400b435b024cd21061f890f8957 }


condition:
	$a0
}