rule Win_Trojan_FM_3
{
strings:
	$a0 = { 01b9ab0680c40083eb0081e91e0183c100268a0289ff88db340126880288d289c0462d000083 }


condition:
	$a0
}