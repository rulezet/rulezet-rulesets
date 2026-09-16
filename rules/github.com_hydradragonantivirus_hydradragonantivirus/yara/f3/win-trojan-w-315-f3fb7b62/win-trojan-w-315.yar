rule Win_Trojan_W_315
{
strings:
	$a0 = { 169090909099b442ff166156f3a55eafabb510b440ff16b43eff16c961e9 }


condition:
	$a0
}