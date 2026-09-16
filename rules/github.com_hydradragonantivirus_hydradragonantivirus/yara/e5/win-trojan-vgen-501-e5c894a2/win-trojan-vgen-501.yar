rule Win_Trojan_VGEN_501
{
strings:
	$a0 = { 01bf0001a5a50e1f8d96b502b41acd21b42ccd2180fa327c0cb4098d969801cd21b400cd16 }


condition:
	$a0
}