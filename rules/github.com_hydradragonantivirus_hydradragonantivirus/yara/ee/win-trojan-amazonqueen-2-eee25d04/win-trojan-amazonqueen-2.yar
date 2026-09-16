rule Win_Trojan_AmazonQueen_2
{
strings:
	$a0 = { 5d81ed03000e1f06b4accd213c30750b2e3b9ed001 }


condition:
	$a0
}