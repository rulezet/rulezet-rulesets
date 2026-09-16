rule Win_Trojan_VGEN_560
{
strings:
	$a0 = { 1e0e1fe800005e81ee9e018a848c012ea20201b42fcd218c844903899c4b03b41a8d944d03cd21b82435cd218c847d }


condition:
	$a0
}