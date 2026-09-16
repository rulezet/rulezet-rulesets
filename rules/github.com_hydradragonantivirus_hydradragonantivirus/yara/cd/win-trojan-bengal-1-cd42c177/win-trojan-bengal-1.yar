rule Win_Trojan_Bengal_1
{
strings:
	$a0 = { e89e00720f0e1f33f6e83400e8f200061fe877001f1e07e89e00fa2ea113002ea348022ea115002ea34a028cd82e01 }


condition:
	$a0
}