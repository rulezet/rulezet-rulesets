rule Win_Trojan_AHAV_1
{
strings:
	$a0 = { 40b950018d960001cd21b8004233c933d2cd21b440b904008d963902cd21b800578b9640028b8e }


condition:
	$a0
}