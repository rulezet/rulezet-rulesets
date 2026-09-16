rule Win_Trojan_PS_27
{
strings:
	$a0 = { 868f0201b41a8d966402cd21b82435cd21899e60028c86 }


condition:
	$a0
}