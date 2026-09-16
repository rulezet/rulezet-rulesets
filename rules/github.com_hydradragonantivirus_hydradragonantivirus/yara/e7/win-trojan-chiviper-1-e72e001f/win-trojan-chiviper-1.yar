rule Win_Trojan_Chiviper_1
{
strings:
	$a0 = { 25733f6431303d2573266431313d2573266432313d2564266432323d2573 }


condition:
	$a0
}