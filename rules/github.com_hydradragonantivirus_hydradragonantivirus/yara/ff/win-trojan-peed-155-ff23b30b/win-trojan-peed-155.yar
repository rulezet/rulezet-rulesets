rule Win_Trojan_Peed_155
{
strings:
	$a0 = { e80c000000f7db29dff7db01de89c3eb1b59e886000000bfd4464000bb59f3ffff81c3 }


condition:
	$a0
}