rule Win_Virus_Ramnit_1851
{
strings:
	$a0 = { 83ec046031??4?c1e?065?b?0?0?0000 }


condition:
	$a0
}