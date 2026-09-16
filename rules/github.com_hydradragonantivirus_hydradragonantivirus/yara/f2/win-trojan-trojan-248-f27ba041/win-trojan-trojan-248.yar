rule Win_Trojan_Trojan_248
{
strings:
	$a0 = { 0300a38200b440b936019033d2cd21b8004233c933d2cd21b440b90500ba8100cd21b43ecd21eb }


condition:
	$a0
}