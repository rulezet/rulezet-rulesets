rule Win_Trojan_RetHunter_2
{
strings:
	$a0 = { b901008d562890cd21b0013cc3750de81200b440b95a008d56f7cd21b43ecd21b44febc5b802 }


condition:
	$a0
}