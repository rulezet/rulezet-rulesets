rule Win_Trojan_BrokenHeart_1
{
strings:
	$a0 = { 0132e4cd1a80e2137403e92d01be20018bfeb98e00ad353412abe2f9908e6035a675df15a8b41307db802ef933 }


condition:
	$a0
}