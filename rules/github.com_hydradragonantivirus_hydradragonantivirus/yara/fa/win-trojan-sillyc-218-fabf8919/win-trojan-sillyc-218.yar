rule Win_Trojan_SillyC_218
{
strings:
	$a0 = { e93501b800438bd681c2580383c21ecd21898ce102b80143b900008bd681c2580383c21ecd21 }


condition:
	$a0
}