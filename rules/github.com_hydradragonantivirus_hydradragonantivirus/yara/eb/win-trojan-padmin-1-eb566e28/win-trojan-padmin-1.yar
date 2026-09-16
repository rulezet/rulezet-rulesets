rule Win_Trojan_Padmin_1
{
strings:
	$a0 = { b742264eb8150673c6122a632ce0ba2ef35334c8c12e0648c67a616557a92f7b7ed2163a152b3ece7aba22364bf07f787a9b2d0c0730be5f2db924de3a8b5764 }


condition:
	$a0
}