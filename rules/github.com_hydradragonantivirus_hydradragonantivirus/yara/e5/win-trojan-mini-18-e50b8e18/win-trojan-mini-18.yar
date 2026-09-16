rule Win_Trojan_Mini_18
{
strings:
	$a0 = { 91d9bae2fbf7eacd2193b43f8bd6b9cbfccd213bc17439803c4d7434803c5a742f83c07a502bc9 }


condition:
	$a0
}