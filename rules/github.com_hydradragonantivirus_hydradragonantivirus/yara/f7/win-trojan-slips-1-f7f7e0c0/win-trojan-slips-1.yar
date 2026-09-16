rule Win_Trojan_Slips_1
{
strings:
	$a0 = { cd21721d8cc82e0106a9052e0106b105fa2e8e16a9 }


condition:
	$a0
}