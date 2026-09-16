rule Win_Trojan_F_1
{
strings:
	$a0 = { 53b9c5025133d2cd00593bc175d1 }


condition:
	$a0
}