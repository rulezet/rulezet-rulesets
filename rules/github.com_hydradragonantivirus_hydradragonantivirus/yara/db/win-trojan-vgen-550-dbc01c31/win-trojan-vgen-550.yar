rule Win_Trojan_VGEN_550
{
strings:
	$a0 = { cd21e80000444489e58b76fe83ee083d649f7503e9700006bf0300b80358bb0100cd21b80158bb8100cd21b448 }


condition:
	$a0
}