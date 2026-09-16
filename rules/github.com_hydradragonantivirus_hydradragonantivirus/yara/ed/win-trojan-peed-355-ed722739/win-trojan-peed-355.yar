rule Win_Trojan_Peed_355
{
strings:
	$a0 = { 3dee0c00007c3fb957c944ff4881c1ff45bb00ba80080800c1 }


condition:
	$a0
}