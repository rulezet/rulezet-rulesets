rule Win_Trojan_Industrial_1
{
strings:
	$a0 = { fc037426cdf17327505306b800008ec0fa26a1c403268b }


condition:
	$a0
}