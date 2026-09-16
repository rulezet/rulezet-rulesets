rule Win_Trojan_FireFly_1
{
strings:
	$a0 = { b9000181370000817702000083c304e2f2 }


condition:
	$a0
}