rule Win_Trojan_Burg792_1
{
strings:
	$a0 = { 5203268904bedd03268a1c80fb3974 }


condition:
	$a0
}