rule Win_Trojan_Checksum_1
{
strings:
	$a0 = { 538bdab834129c9d03079c4343e2f89d }


condition:
	$a0
}