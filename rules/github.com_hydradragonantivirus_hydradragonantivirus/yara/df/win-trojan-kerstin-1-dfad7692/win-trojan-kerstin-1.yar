rule Win_Trojan_Kerstin_1
{
strings:
	$a0 = { 04a11a008b161c00f81bc183da000f829a00b91000f7f1268916a60026a3a800268306a0003a }


condition:
	$a0
}