rule Win_Trojan_C_16
{
strings:
	$a0 = { 2d03008986a701b440b9c5008d960601cd21b800422bc999cd21b440b904008d96a601cd21 }


condition:
	$a0
}