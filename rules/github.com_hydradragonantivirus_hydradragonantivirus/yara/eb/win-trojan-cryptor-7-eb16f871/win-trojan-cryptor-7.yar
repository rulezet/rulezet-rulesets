rule Win_Trojan_Cryptor_7
{
strings:
	$a0 = { e8230c8bf703f983c710b401e8170cb4408bd7cd21b800422bc92bd2cd21b440b904008d96 }


condition:
	$a0
}