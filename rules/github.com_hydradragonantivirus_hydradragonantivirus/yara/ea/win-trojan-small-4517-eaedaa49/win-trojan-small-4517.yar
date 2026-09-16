rule Win_Trojan_Small_4517
{
strings:
	$a0 = { b821a6e50f2d2164a50f5050e8 }


condition:
	$a0
}