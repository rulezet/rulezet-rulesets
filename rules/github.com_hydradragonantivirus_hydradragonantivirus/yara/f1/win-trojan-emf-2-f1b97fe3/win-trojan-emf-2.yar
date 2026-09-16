rule Win_Trojan_EMF_2
{
strings:
	$a0 = { e800005de421500c02e621b94c018db6 }


condition:
	$a0
}