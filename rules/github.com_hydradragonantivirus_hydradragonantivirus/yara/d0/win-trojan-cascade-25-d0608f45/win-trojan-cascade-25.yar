rule Win_Trojan_Cascade_25
{
strings:
	$a0 = { 8db74d01bc????31343124464c75f8 }


condition:
	$a0
}