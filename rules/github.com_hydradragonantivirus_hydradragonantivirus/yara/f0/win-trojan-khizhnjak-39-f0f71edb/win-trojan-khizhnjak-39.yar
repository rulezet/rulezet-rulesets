rule Win_Trojan_Khizhnjak_39
{
strings:
	$a0 = { b80042cd217232ba1001b9840290b440cd217225b90000ba0000b80042cd217218ba0b03b903 }


condition:
	$a0
}