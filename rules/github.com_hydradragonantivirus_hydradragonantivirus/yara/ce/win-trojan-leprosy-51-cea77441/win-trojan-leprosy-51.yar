rule Win_Trojan_Leprosy_51
{
strings:
	$a0 = { e9500100008b1e530253e810005b90b99a02ba0001b440cd21e80100c3bb34 }


condition:
	$a0
}