rule Win_Trojan_Small_4069
{
strings:
	$a0 = { 9090909090b8??0240008b700c81c600004000bf??f24000e8??0000008b0e8b }


condition:
	$a0
}