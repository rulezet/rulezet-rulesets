rule Win_Trojan_Vundo_26
{
strings:
	$a0 = { 60e8691e0000737b643c00004652efe8e6190000a0591e6d851c2b0000f658f0 }


condition:
	$a0
}