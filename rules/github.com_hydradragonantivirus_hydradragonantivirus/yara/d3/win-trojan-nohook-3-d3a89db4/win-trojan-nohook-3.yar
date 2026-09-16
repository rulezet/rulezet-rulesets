rule Win_Trojan_NoHook_3
{
strings:
	$a0 = { 02b94e00f3a4c51e0a00c647ff85cd200018020000b8013dcd21930e1fb440b9 }


condition:
	$a0
}