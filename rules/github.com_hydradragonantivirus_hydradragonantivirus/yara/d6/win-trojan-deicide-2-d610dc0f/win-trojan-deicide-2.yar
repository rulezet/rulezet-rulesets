rule Win_Trojan_Deicide_2
{
strings:
	$a0 = { 02dada9c505351521e06165657a12b0aa3270a8b1e2d0a }


condition:
	$a0
}