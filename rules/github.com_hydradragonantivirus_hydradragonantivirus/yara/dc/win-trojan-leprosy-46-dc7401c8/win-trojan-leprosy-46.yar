rule Win_Trojan_Leprosy_46
{
strings:
	$a0 = { 01fa53fbe81600905bfbb440faba0001fab99a02fb }


condition:
	$a0
}