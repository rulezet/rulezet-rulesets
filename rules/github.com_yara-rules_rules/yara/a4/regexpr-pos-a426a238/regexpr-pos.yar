rule regexpr_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS malware - RegExpr"
strings:
	$s1 = "RegExpr" nocase
	$s2 = "Data.txt"
	$s3 = "Track1"
	$s4 = "Track2"
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}