rule Win_Trojan_SdBot_4599
{
strings:
	$a0 = { 50494e47 }

	$a1 = { 72756e73646c6c732e657865 }


condition:
	$a0 and $a1
}