rule Win_Trojan_Khizhnjak_13
{
strings:
	$a0 = { 028b1ee302b80042cd217233ba1001b9fe01908b1ee302b440cd217222b90000ba00008b1e }


condition:
	$a0
}