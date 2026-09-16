rule Win_Spyware_DiabloII_1
{
strings:
	$a0 = { 546d6aff3f849d3b6353444941424c4f2041435449564575df0876a74469e66f20 }


condition:
	$a0
}