rule Win_Trojan_DiskBoomer_2
{
strings:
	$a0 = { c9b404cd1a81fa06097503e92f01bb4c008b072ea3417cbb4e008b072ea3437cbb13048b074889 }


condition:
	$a0
}