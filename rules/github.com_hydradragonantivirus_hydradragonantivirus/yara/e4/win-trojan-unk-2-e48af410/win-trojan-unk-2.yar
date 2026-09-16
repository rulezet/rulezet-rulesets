rule Win_Trojan_unk_2
{
strings:
	$a0 = { e800005e83ee0eb8784bcd213d4b78743c8cd8488ed8803e00005a7530812e12004400812e030044 }


condition:
	$a0
}