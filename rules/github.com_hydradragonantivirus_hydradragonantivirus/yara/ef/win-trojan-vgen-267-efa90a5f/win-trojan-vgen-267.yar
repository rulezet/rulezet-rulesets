rule Win_Trojan_VGEN_267
{
strings:
	$a0 = { 6401bb15002e8137493643434e75f6a136496bc8db5f37c8ca1a7f3d3dc4809037f6364861eddd58284f3856384ebb }


condition:
	$a0
}