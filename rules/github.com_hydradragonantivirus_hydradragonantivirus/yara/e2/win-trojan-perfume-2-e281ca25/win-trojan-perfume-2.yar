rule Win_Trojan_Perfume_2
{
strings:
	$a0 = { ef408ec70e1fb90004fcbf0000f3a481ec0004 }


condition:
	$a0
}