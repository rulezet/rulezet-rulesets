rule Win_Trojan_Lesson_4
{
strings:
	$a0 = { b931018bd6cd21e80300c39900bf460003feb9720053bb2a0003de8b175b2e311583c702e2f8 }


condition:
	$a0
}