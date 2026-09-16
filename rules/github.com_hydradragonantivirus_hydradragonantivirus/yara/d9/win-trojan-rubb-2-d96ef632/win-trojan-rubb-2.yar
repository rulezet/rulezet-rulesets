rule Win_Trojan_Rubb_2
{
strings:
	$a0 = { 33c933d29cfaff1ede048b0ee204b8fa0303c8ba0010b4409cfaff1ede04c3 }


condition:
	$a0
}