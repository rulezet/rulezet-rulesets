rule Win_Trojan_Apdoor_2
{
strings:
	$a0 = { 37f8ef635000687474703a2f2f734e4e45435420041bdc11663a2043236eb47d6a }


condition:
	$a0
}