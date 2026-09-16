rule Win_Trojan_Small_4433
{
strings:
	$a0 = { e8040000000076400089e20f6e1a0f7ed88b0083c40450 }


condition:
	$a0
}