rule Win_Trojan_BadSectors1_2
{
strings:
	$a0 = { 4b7503e961093d003d7503e9590980fc4e7503e9af09 }


condition:
	$a0
}