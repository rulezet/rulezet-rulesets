rule Win_Trojan_Aga_1
{
strings:
	$a0 = { 28ba164fb902128bfe0e071e33c08ed889160400fc2eadd3c82b060400abfecd75f3441f6d24deee6bc8893c99e1 }


condition:
	$a0
}