rule Win_Trojan_Sinister_1
{
strings:
	$a0 = { 0483ea038bf206b8bfabcd213d56987403eb0490eb3b908cc0488ed8bb03008b072d5f008907 }


condition:
	$a0
}