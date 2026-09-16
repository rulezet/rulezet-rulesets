rule Win_Trojan_Leprosy_8
{
strings:
	$a0 = { 0c32e80300e9150451be3a018bfeb96607fcad33060301ab4975f759c3ba00018b1efc0453b92c06e8ddff5bb80040cd2153e8d3ff5bc3 }


condition:
	$a0
}