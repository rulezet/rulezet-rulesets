rule Win_Trojan_Lith_2
{
strings:
	$a0 = { b10133d2b94302b440cd2133c9b80042cd21b90300bab00190b440cd21e92001c6064202ff33c9 }


condition:
	$a0
}