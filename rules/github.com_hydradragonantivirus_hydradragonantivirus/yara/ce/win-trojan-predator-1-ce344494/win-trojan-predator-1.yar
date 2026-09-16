rule Win_Trojan_Predator_1
{
strings:
	$a0 = { 4d49cd213d4d497503e9e9008cc8488ed8803e00005a75f1bb4504b104d3eb43291e030003 }


condition:
	$a0
}