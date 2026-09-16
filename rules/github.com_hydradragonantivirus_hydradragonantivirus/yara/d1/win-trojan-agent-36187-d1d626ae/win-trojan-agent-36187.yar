rule Win_Trojan_Agent_36187
{
strings:
	$a0 = { 68a1ef4100ff35140042005bffd3a3b7ef410003c62bc62bc608e0436609e02b }


condition:
	$a0
}