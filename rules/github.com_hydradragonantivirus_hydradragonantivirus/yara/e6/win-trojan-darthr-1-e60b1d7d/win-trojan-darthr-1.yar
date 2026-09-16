rule Win_Trojan_Darthr_1
{
strings:
	$a0 = { b82012e86900268a1db81612e86000 }


condition:
	$a0
}