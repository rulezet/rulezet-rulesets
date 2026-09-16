rule Win_Trojan_Spoofer_10
{
strings:
	$a0 = { e8c3fdffff83c41089c0668945ee83c4fc6a006a026a02e8ccfdffff83c41089c08945e483c4fc6a108d55ec89d0508b45e450e8a0fdffff83c4108b55e489d0eb06 }

	$a1 = { 6f6f6665642061732025730a00466c6f6f }


condition:
	$a0 and $a1
}