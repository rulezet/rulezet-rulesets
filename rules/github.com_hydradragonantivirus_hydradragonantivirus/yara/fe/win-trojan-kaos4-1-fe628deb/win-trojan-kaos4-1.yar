rule Win_Trojan_Kaos4_1
{
strings:
	$a0 = { fc8db6b502bf0001a5a5b8fffef7d050c3f9e93501 }


condition:
	$a0
}