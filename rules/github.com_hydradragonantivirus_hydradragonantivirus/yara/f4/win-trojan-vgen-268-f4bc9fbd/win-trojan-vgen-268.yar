rule Win_Trojan_VGEN_268
{
strings:
	$a0 = { 8db6d601bf000157a5a4b8a054cd213d0c127427b844008ec0bf00018d33b91c01fcf3a4061fb82135cd218c06 }


condition:
	$a0
}