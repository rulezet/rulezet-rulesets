rule Win_Trojan_F_You_2
{
strings:
	$a0 = { c835ffff587402ffe0e95cffb00231d231c9b442cd }


condition:
	$a0
}