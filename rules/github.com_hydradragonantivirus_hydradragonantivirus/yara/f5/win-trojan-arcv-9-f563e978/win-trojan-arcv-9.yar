rule Win_Trojan_ARCV_9
{
strings:
	$a0 = { 05100033db4b8be38ed0e80502a1fb028cc303c3a354 }


condition:
	$a0
}