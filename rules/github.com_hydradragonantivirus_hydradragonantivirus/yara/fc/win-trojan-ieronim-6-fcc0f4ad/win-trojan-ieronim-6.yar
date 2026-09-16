rule Win_Trojan_Ieronim_6
{
strings:
	$a0 = { bbba7981ebb7795351b9b80e81c174f32e8137e73a81c3731d81eb711de2f1 }


condition:
	$a0
}