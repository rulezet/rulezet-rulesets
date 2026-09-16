rule Win_Trojan_Multiface_2
{
strings:
	$a0 = { be040103f38bde2e803e04013c75062ec6878a0101 }


condition:
	$a0
}