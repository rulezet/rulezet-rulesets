rule Win_Trojan_OneHalf_11
{
strings:
	$a0 = { b6b39a7b6636430c6ccdac9def68c4260cf648ba874b28032f10dcd8bc688cf6533f20cb52c76c91fb574cd402e2ae96 }


condition:
	$a0
}