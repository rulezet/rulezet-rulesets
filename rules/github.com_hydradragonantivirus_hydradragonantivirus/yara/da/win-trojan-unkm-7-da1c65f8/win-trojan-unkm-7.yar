rule Win_Trojan_Unkm_7
{
strings:
	$a0 = { 96ca02cd217215e81d007410b43ecd21b8004fcd217205e80d0075f0e8f600ba8000b41acd21c3 }


condition:
	$a0
}