rule Win_Trojan_AmazonQueen_1
{
strings:
	$a0 = { 5d81ed03000e1f06b4accd213c30750b2e3b9ecf01 }


condition:
	$a0
}