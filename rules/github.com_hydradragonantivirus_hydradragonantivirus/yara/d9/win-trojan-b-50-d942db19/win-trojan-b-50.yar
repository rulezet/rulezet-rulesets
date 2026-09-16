rule Win_Trojan_B_50
{
strings:
	$a0 = { 03c60634007733dbb90100ba8000cd13e8d800b200c606340064b80102 }


condition:
	$a0
}