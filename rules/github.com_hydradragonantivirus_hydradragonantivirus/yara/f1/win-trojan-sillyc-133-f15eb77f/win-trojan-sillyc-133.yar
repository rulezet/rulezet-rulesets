rule Win_Trojan_SillyC_133
{
strings:
	$a0 = { 8905b440cd21ba0000b9f100b440cd21b90000ba0000b80042cd21b90600baeb00b440cd21 }


condition:
	$a0
}