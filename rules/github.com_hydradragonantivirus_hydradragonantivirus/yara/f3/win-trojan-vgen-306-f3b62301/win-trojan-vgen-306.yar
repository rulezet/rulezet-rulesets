rule Win_Trojan_VGEN_306
{
strings:
	$a0 = { e800005d83ed05bb0000bf3f00b9d5012e311b47e5428bf0e5423bc67518a480ad88ab8ee4942da493a12c774562 }


condition:
	$a0
}