rule Win_Trojan_Gbot_7552
{
strings:
	$a0 = { 2bc9558bec81c4c0fdffff8d4c24446aff6a006a006a0083e1fe516a0050488909a9ffefffff7402e128ff15??????0083c408f88d0881c95f410700 }


condition:
	$a0
}