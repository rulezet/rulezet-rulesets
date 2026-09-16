rule Win_Trojan_BDFactory_6
{
strings:
	$a0 = { 9090609cfc90e8c10000006089e531d290648b52308b520c8b5214eb02 }


condition:
	$a0
}