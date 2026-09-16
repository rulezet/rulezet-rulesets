rule Win_Trojan_Crypt_251
{
strings:
	$a0 = { 6882f3550083e00064ff306489208838c05060eb02eb11e800000000ff34 }


condition:
	$a0
}