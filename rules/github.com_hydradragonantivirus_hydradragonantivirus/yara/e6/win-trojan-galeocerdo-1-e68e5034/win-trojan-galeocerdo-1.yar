rule Win_Trojan_Galeocerdo_1
{
strings:
	$a0 = { b440cd21b8004233d233c9bf58033e8b1bcd21b440bf58033e8b1bb90300ba350303d5cd21 }


condition:
	$a0
}