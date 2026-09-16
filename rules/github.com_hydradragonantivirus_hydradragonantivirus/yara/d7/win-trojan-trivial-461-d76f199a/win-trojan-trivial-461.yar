rule Win_Trojan_Trivial_461
{
strings:
	$a0 = { cd21b42bb9d007b601b201cd21b8023dba9e00cd21b440b96800ba0001cd21b43ecd21c32a2e }


condition:
	$a0
}