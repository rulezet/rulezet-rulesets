rule Win_Trojan_Borg_4
{
strings:
	$a0 = { cd2000909050599090b811ea93909087d987cab9344887cb90909392cd16b9 }


condition:
	$a0
}