rule Win_Trojan_Whale_23
{
strings:
	$a0 = { e80000eb0d8bd0588bd85891ff166625 }


condition:
	$a0
}