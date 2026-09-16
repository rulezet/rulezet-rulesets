rule Win_Trojan_Vulcan_6
{
strings:
	$a0 = { cd213c93c3fc06b82135cd21891ebe018c06c0015848 }


condition:
	$a0
}