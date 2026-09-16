rule Win_Trojan_PJ_1
{
strings:
	$a0 = { 40b9be008bd7cd21b8004233c933d2cd21b440b905008bd781c2b000cd21b43ecd21c32a2e636f }


condition:
	$a0
}