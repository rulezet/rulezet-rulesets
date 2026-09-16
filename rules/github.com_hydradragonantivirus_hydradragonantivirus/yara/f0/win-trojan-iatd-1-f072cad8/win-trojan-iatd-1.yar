rule Win_Trojan_IATD_1
{
strings:
	$a0 = { cd21891e38018c063a01b425ba1901cd21ba3c01cd271e565033f68edec57404ff34c604cf }


condition:
	$a0
}