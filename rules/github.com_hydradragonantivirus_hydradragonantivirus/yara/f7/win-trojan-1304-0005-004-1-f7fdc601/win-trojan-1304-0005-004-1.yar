rule Win_Trojan__1304_0005_004_1
{
strings:
	$a0 = { 4515000026c745170000bafb06b440cd21268b4d0d268b550fd0ce80c664d0c6b80157cd21 }


condition:
	$a0
}