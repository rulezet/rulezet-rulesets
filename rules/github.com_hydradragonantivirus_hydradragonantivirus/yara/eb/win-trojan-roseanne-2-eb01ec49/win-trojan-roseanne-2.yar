rule Win_Trojan_Roseanne_2
{
strings:
	$a0 = { 2700b440b9f100ba6400cd21b80157538b4f168b57185bcd21b43ecd2133c9bb80008a4f15 }


condition:
	$a0
}