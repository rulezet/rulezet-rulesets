rule Win_Trojan_Tankar_2
{
strings:
	$a0 = { b80042cd21b43fba9c0259cd21803e9d02eb7421c6060001e9b43ffec450ba0301b99901cd21b8 }


condition:
	$a0
}