rule Win_Trojan_Gidra_2
{
strings:
	$a0 = { 0e1fe800005e81ee9e018a848c012ea20201b42fcd218c844503899c4703b41a8d944903cd21b82435cd218c8479 }


condition:
	$a0
}