rule Win_Trojan_Tamanna_1
{
strings:
	$a0 = { 803e00005a7507263b06010075e1c306e8d1ff8b1e0400 }


condition:
	$a0
}