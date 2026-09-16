rule Win_Trojan_Little_5
{
strings:
	$a0 = { 4eb92700ba5d01cd21720ee816007504b44febf3b8014ccd21fab40299b90001cd26ebfeb8023dba9e00cd2193b43fb90200ba5b01cd21813e5b018bf6 }


condition:
	$a0
}