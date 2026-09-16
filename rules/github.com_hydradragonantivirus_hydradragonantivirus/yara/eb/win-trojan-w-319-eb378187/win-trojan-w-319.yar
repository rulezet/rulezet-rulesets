rule Win_Trojan_W_319
{
strings:
	$a0 = { 33c0f3af75159090909099b442ff166156f3a55eabb510b440ff16b43eff16c961e91e0b407f }


condition:
	$a0
}