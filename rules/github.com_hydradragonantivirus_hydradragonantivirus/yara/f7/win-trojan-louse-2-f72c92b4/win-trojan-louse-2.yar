rule Win_Trojan_Louse_2
{
strings:
	$a0 = { e800005dbb8603553680760e??454b75f7 }


condition:
	$a0
}