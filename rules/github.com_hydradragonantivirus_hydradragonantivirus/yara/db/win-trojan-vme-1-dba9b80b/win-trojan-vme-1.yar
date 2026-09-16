rule Win_Trojan_VME_1
{
strings:
	$a0 = { be0000bf0000ba00008b0483c602350000890583c7024a75f0c3 }


condition:
	$a0
}