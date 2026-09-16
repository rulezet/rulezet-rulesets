rule Win_Trojan_Cvir_1
{
strings:
	$a0 = { 20484148419a00001a005589e5bf }


condition:
	$a0
}