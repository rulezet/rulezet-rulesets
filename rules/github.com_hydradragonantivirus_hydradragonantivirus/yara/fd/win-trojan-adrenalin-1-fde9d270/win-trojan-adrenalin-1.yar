rule Win_Trojan_Adrenalin_1
{
strings:
	$a0 = { 8d56fdb440cd218f45028f05b801575a5980c91fcd }


condition:
	$a0
}