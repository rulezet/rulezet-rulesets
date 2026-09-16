rule Win_Trojan_Spambot_13
{
strings:
	$a0 = { 89d0b91701000050055c04000089c28102adde000081323331fd1283e90183f9007c0583ea04ebe7c3 }


condition:
	$a0
}