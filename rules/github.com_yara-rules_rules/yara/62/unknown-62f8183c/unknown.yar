rule unknown
{
meta:
	author = "@patrickrolsen"
	reference = "Unknown POS"
strings:
	$s1 = "a.exe" wide
	$s2 = "Can anyone test" wide
	$s3 = "I m in computer class now" wide
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}