rule Win_Trojan_Kato_1
{
strings:
	$a0 = { 902433c006eb0290248ec026891e040026890e0c000e07e87effe92ffeb4408b1e0200cd63c3 }


condition:
	$a0
}