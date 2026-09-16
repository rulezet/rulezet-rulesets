rule Win_Trojan_Lapidar_1
{
strings:
	$a0 = { 21b8024233c933d2cd21b440b912008d96db01cd21b440b9b4018d961200cd21b801575a59cd21 }


condition:
	$a0
}