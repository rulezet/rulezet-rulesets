rule Win_Trojan_Iframe_48
{
strings:
	$a0 = { 696672616d657769[0-16]3d22687474703a2f2f }

	$a1 = { 2f6c2e68746d223e3c2f696672 }


condition:
	$a0 and $a1
}