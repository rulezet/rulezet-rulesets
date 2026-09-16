rule Win_Trojan_XA_1
{
strings:
	$a0 = { b02c8846ff8b7e00884efe8a4eff000d }


condition:
	$a0
}