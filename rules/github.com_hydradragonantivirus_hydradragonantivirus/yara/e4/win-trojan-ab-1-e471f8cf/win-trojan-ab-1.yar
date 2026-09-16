rule Win_Trojan_Ab_1
{
strings:
	$a0 = { fe0100eb04ff8678fe8b8678fe99bf60009a9f02f5008bf88a8d05008b8678fe05501d7105 }


condition:
	$a0
}