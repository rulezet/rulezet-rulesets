rule Win_Trojan_Uriel_1
{
strings:
	$a0 = { 633a5c636f6d6d616e642e636f6d[0-75]555249454c20312e303007207669727573 }


condition:
	$a0
}