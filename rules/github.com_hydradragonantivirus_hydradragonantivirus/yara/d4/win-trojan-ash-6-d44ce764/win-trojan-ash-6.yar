rule Win_Trojan_Ash_6
{
strings:
	$a0 = { 8db63a0252eb29b41aba8000cd2133c0 }


condition:
	$a0
}