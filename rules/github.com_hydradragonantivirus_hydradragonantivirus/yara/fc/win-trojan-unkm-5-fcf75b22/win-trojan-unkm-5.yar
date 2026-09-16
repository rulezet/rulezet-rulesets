rule Win_Trojan_Unkm_5
{
strings:
	$a0 = { 02cd217215e81a007410b43ecd21b8004fcd217205e80a0075f0ba8000b41acd21c3b8003d }


condition:
	$a0
}