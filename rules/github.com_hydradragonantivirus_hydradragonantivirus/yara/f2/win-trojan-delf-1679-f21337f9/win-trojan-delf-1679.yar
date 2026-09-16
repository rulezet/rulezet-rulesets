rule Win_Trojan_Delf_1679
{
strings:
	$a0 = { 433a5c52554e2e5550 }

	$a1 = { 7474703a2f[0-11]756e6b6e6f77[0-10]2669643d[0-96]54656d705c6e61762e6c6f67 }


condition:
	$a0 and $a1
}