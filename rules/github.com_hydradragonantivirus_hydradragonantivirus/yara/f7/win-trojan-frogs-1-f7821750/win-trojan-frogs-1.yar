rule Win_Trojan_Frogs_1
{
strings:
	$a0 = { 4700b90800babe02bb0010cd2583c4 }


condition:
	$a0
}