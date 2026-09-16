rule Win_Trojan_Eumel_29
{
strings:
	$a0 = { c2d1caaae2f8c33547d9ab4d5dcf17b49afac42aa515973b8c20ae0805fea5a534596df1e0b2c98ef22da30ac923b5 }


condition:
	$a0
}