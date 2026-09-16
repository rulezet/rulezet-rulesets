rule Win_Trojan_Coffeeshop_staticsig_2
{
strings:
	$a0 = { 17f712b78291043882b9868e4f395ec12b5f1ce576c05fee5289d552f6b129ce5f116f0c }


condition:
	$a0
}