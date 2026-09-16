rule Win_Trojan_Froggie_1
{
strings:
	$a0 = { 9572706884180070563459f2255a883c2dab2aed8aa074950d82fa00e205e18bf21468d418 }


condition:
	$a0
}