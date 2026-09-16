rule Win_Trojan_Technomaniac_1
{
strings:
	$a0 = { b8024233c933d2cd21b440ba7cfbb90b03cd21b8004233c933d2cd21b440ba0001b90b03cd21 }


condition:
	$a0
}