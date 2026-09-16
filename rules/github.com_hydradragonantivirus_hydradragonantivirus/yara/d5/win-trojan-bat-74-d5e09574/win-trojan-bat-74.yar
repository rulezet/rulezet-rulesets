rule Win_Trojan_BAT_74
{
strings:
	$a0 = { 636f7079202561252b2525732b25302b2561252b25257320252573 }


condition:
	$a0
}