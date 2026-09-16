rule Win_Trojan_Cascade_10
{
strings:
	$a0 = { 4d01bc82063134903124464c75f7 }


condition:
	$a0
}