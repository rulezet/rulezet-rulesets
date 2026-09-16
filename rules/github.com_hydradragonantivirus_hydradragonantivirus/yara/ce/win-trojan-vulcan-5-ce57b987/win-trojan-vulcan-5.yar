rule Win_Trojan_Vulcan_5
{
strings:
	$a0 = { cd213c93c3fc0606b82135cd21891ebe018c06c00158 }


condition:
	$a0
}