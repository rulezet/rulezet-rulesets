rule Win_Trojan_Spyer_1
{
strings:
	$a0 = { b80242b9ffffbad6ffcd217303e90a01052a003d03007703 }


condition:
	$a0
}