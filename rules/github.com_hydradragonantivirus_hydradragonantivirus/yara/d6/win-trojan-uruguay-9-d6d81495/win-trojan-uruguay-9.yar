rule Win_Trojan_Uruguay_9
{
strings:
	$a0 = { 263105f6d6f7ddd1d23e02142bd203eaf6d6263215eb0013d0d1e5d1e583 }


condition:
	$a0
}