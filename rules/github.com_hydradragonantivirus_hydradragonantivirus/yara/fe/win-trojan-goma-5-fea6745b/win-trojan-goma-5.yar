rule Win_Trojan_Goma_5
{
strings:
	$a0 = { e800005d81ed2a01b44e2efe861f018d961f01cd212efe8e1f01eb0790b44fcd21721ab8023dba9e00cd218bd8b96600ba0001b440cd21b43ecd21ebe0cd20 }


condition:
	$a0
}