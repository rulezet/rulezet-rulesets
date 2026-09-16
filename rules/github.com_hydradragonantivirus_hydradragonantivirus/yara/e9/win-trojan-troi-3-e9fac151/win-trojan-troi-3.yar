rule Win_Trojan_Troi_3
{
strings:
	$a0 = { d2cd21b440b9420190ba0002cd21cc5ab80157cd21 }


condition:
	$a0
}