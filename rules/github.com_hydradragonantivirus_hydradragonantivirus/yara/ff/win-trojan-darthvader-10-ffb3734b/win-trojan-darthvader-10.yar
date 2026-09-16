rule Win_Trojan_DarthVader_10
{
strings:
	$a0 = { 0450e803fd58ba0001035604b9e003b440cd21bf6005037e048b0d8b5502b001b457cd21b43e }


condition:
	$a0
}