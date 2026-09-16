rule reg_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS malware - RegExpr"
strings:
	$s1 = "T1_FOUND: %s"
	$s2 = "id=%s&log=%s"
	$s3 = "\\d{15,19}=\\d{13,}"
condition:
	uint16(0) == 0x5A4D and 2 of ($s*)
}