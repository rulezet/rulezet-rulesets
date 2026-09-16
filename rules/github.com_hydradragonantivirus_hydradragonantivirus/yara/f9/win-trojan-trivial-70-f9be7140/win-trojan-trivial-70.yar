rule Win_Trojan_Trivial_70
{
strings:
	$a0 = { 33c9b405cd1380fe017404fec6ebf380fd197406fecefec5ebe880fa827406fec232f6ebdb }


condition:
	$a0
}