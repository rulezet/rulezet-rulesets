rule Win_Trojan_Trivial_77
{
strings:
	$a0 = { 4eb92700ba7d01cd21726ee80b007504b44febf3b8014ccd21b8023dba9e00cd2193b42acd21983d040074317427b43fb90200ba5e01cd21813e5e018b }


condition:
	$a0
}