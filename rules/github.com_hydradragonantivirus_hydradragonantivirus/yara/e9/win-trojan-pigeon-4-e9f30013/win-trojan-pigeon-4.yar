rule Win_Trojan_Pigeon_4
{
strings:
	$a0 = { 6765746b65792e646c6c00536574434e6b6579686f6f6b00 }


condition:
	$a0
}