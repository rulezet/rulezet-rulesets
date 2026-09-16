rule Win_Trojan_Tiny_6
{
strings:
	$a0 = { f3a4b44eb16487d1fec6cd21730b1fb41a99b280cd210e1fcbb8023d99b29ecd2193b43fb2 }


condition:
	$a0
}