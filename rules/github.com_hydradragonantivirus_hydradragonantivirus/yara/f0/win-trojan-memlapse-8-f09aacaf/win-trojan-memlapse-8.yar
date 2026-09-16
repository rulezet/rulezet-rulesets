rule Win_Trojan_MemLapse_8
{
strings:
	$a0 = { b2e988167603b440ba0000b97603cd21075f570626c745150000b90300b440ba7603cd2107 }


condition:
	$a0
}