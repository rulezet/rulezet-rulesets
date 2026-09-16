rule Win_Trojan_Loz_7
{
strings:
	$a0 = { 06bf000157b90300f3a4b887e9cd210bc07503eb63908cd8488ed88b1e030083eb3d7303eb5290b44acd21b448 }


condition:
	$a0
}