rule Win_Trojan_WildThing_2
{
strings:
	$a0 = { 01b905028ab62c038a2732e6882743e2f75bc3 }


condition:
	$a0
}