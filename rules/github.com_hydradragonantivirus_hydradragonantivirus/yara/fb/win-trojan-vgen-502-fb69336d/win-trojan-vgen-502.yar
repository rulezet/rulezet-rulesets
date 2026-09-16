rule Win_Trojan_VGEN_502
{
strings:
	$a0 = { 01bf0001a5a50e1f8d962f02b41acd21b8013580ec10bb00008ec3cd21b003cd21b42ccd21 }


condition:
	$a0
}