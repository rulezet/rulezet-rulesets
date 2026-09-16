rule Win_Trojan_Dutch_2
{
strings:
	$a0 = { 4232c08b1e8c0133c933d2cd21b9f40481e90001b440 }


condition:
	$a0
}