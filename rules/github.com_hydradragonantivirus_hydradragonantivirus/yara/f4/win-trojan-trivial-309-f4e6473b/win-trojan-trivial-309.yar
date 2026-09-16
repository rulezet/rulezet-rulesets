rule Win_Trojan_Trivial_309
{
strings:
	$a0 = { 2e2a00b44e33c9ba000152cd21721bb8013dba9e00cd2193b440b1365acd21b43ecd21b44febe02e2e00b43b5aba2801cd2173cbc3 }


condition:
	$a0
}