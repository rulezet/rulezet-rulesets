rule Win_Trojan_Cryptor_8
{
strings:
	$a0 = { 7d14e8190d5b8bf703f983c710b401e80c0db4408bd7cd21b800422bc92bd2cd21b440b904008d }


condition:
	$a0
}