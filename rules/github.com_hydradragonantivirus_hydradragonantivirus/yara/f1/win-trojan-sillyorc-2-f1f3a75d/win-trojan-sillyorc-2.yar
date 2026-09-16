rule Win_Trojan_SillyORC_2
{
strings:
	$a0 = { cd213d0500753ab82b35cd218c062901b021cd2106583d60007426b860008ec00e1f33ffbe0001b97000fcf3a4b8 }


condition:
	$a0
}