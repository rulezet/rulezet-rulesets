rule Win_Trojan_PS_28
{
strings:
	$a0 = { 910201b41a8d966602cd21b82435cd21899e62028c86 }


condition:
	$a0
}