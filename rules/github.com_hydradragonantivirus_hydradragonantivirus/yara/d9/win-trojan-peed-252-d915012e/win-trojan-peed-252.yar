rule Win_Trojan_Peed_252
{
strings:
	$a0 = { bade74b40b85c287de73475589e55150b80100000048506a00 }


condition:
	$a0
}