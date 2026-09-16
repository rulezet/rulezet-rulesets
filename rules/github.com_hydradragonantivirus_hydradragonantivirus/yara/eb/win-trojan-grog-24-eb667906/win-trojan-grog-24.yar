rule Win_Trojan_Grog_24
{
strings:
	$a0 = { e8ab007303e9940093b80057e89f002e89160b012e }


condition:
	$a0
}