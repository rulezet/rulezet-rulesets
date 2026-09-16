rule Win_Trojan_Moon_2
{
strings:
	$a0 = { bf5801abbf5c01ab59b44ecd21721eb8023d2bd2b29ecd2193b4402bd2fec633c9b163cd21b43e }


condition:
	$a0
}