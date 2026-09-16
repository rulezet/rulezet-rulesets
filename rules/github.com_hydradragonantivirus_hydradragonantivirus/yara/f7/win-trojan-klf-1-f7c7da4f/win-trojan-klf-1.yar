rule Win_Trojan_KLF_1
{
strings:
	$a0 = { 3dcdfd72ae8bd80e1fb80057cdfd72a6890e6c038916 }


condition:
	$a0
}