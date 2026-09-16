rule Win_Trojan_BOO_19
{
strings:
	$a0 = { 4b75f15b5e8bce81e90005c1e902fdad51ad8bc8ad8bd0b280be0400b81003cd13fec680fe10 }


condition:
	$a0
}