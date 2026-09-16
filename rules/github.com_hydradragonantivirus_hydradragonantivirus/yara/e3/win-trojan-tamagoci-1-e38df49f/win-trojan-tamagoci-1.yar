rule Win_Trojan_Tamagoci_1
{
strings:
	$a0 = { 47f26ebd3a8430dff09e616688bd674dd598b2f7ef1008827ddcee3463fc3854b211653a7db989ff }


condition:
	$a0
}