rule Win_Trojan_Admiral_1
{
strings:
	$a0 = { 408b9e28028d960001b94e01cd21b8004233c933d2cd21b440b91a008d964e02cd21b43ecd21c3 }


condition:
	$a0
}