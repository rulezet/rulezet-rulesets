rule Win_Trojan_Screamer_3
{
strings:
	$a0 = { 2eb9ff00f2aee32889fe26ad25dfdf3d434f74113d }


condition:
	$a0
}