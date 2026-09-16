rule Win_Trojan_Phoenix_5
{
strings:
	$a0 = { cd2f06b0f5e66033c0e6618ec093ab58abba8000b901 }


condition:
	$a0
}