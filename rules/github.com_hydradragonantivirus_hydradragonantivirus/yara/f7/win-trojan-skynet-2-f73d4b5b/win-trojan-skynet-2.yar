rule Win_Trojan_SkyNet_2
{
strings:
	$a0 = { 03b4408d960001b99f02cd21b8004233c933d2cd21b440b91c008d96eb03cd21b801573e }


condition:
	$a0
}