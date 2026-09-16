rule sets_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS malware - Sets"
strings:
	$s1 = "GET /sets.txt"
condition:
	uint16(0) == 0x5A4D and $s1
}