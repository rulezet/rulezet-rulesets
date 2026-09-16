rule Win_Trojan_Jackel_1
{
strings:
	$a0 = { 40b90c000e1fba3f02cd21b8024233c933d2cd21b440b9c9020e1fba0001cd215a59b457b001cd }


condition:
	$a0
}