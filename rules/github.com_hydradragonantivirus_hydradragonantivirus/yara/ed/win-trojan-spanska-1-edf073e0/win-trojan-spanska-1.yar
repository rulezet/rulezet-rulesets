rule Win_Trojan_Spanska_1
{
strings:
	$a0 = { 8a96f604b9b3038db63e018bfe8a044632c2e8d5ffe2f6 }


condition:
	$a0
}