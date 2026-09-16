rule Win_Trojan_Skater_2
{
strings:
	$a0 = { c62ad37f6ad86263af4bd0f76926d32a10a9668a99634bbf5d12a8ab1134b207f3668a13aaf4 }


condition:
	$a0
}