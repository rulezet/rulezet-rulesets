rule Win_Trojan_AmazonQueen_6
{
strings:
	$a0 = { e800005d81ed050006b4accd213c3075132e3b9ee001 }


condition:
	$a0
}