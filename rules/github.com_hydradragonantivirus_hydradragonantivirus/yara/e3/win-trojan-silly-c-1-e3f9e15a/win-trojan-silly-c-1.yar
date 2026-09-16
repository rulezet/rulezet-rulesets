rule Win_Trojan_Silly_C_1
{
strings:
	$a0 = { 8901b440b990008d960001cd21b800422bc999cd21b440b904008d968801cd21b43ecd21b44f }


condition:
	$a0
}