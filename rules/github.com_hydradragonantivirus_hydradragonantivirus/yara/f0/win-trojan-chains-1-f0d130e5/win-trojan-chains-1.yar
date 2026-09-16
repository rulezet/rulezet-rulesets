rule Win_Trojan_Chains_1
{
strings:
	$a0 = { 8cc8488ec026832e030038268b1e030003d8438ec333c08b0e59018b365b0133ff51ac5056d1e8d1e88bc8f3a4ad8b }


condition:
	$a0
}