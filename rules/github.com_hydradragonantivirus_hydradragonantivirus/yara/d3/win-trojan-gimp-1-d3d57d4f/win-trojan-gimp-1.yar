rule Win_Trojan_Gimp_1
{
strings:
	$a0 = { 33db8ed38edbbe007c8be68bfbb9fdff018c13888b841388b106d3e0b900018ec050fcf3a5b884 }


condition:
	$a0
}