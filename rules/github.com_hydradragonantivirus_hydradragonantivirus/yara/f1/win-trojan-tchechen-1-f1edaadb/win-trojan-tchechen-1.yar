rule Win_Trojan_Tchechen_1
{
strings:
	$a0 = { 33c08ec0268916000233d2268716000258073bc27402cd202e301480c2 }


condition:
	$a0
}