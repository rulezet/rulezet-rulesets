rule Win_Trojan_L_20
{
strings:
	$a0 = { 58298b0e0c0251e810005bb93c0290ba0001b440cd21e80100c3 }


condition:
	$a0
}