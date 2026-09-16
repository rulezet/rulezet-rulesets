rule Win_Trojan_Grog_21
{
strings:
	$a0 = { 3dcd218bd80e1f723ab43fb90a008bd58bfa83c20a8b }


condition:
	$a0
}