rule Win_Trojan_C1992_1
{
strings:
	$a0 = { c9b4428b1e0205e87b02c3b43f8b1e0205badc04e86e02c3badc04b4408b1e0205e86102c3 }


condition:
	$a0
}