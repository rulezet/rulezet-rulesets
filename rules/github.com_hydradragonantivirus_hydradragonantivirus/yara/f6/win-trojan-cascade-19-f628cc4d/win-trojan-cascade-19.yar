rule Win_Trojan_Cascade_19
{
strings:
	$a0 = { 01f687290101740f8db74b01bc880631343124464c75f8 }


condition:
	$a0
}