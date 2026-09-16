rule Win_Trojan_Horse_10
{
strings:
	$a0 = { 13e86703b81335e85a0353062e891e42 }


condition:
	$a0
}