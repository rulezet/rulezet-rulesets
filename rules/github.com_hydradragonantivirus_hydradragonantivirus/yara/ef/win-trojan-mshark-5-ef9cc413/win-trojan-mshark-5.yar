rule Win_Trojan_Mshark_5
{
strings:
	$a0 = { 7501ba000003d6cd21e83900ebbe }


condition:
	$a0
}