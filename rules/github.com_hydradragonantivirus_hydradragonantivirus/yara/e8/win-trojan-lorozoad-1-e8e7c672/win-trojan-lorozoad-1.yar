rule Win_Trojan_Lorozoad_1
{
strings:
	$a0 = { 76322e302e3530373237 }

	$a1 = { 4b4c4153482e5265736f7572636573 }


condition:
	$a0 and $a1
}