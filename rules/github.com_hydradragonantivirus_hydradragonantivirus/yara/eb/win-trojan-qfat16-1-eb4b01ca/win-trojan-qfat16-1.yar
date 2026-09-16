rule Win_Trojan_QFat16_1
{
strings:
	$a0 = { 5033c050e85d0e83c40a0bc07410b8820650e82a0559b8010050e8fb0159b8c00650e84f05 }


condition:
	$a0
}