rule Win_Trojan_INT_1
{
strings:
	$a0 = { e20050bf4c005733ed8eddc41dbf7402 }


condition:
	$a0
}