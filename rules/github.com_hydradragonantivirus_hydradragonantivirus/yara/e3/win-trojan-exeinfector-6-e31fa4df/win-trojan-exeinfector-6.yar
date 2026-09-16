rule Win_Trojan_ExeInfector_6
{
strings:
	$a0 = { 2a2e45584500 }

	$a1 = { b44e[0-8]cd21[0-200]b43d[0-8]cd21[0-200]b440[0-8]cd21 }


condition:
	$a0 and $a1
}