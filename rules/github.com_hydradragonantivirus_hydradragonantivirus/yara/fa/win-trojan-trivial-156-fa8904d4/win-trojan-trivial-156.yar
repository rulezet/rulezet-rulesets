rule Win_Trojan_Trivial_156
{
strings:
	$a0 = { 01b44ecd21ba9e00b8013dcd218bd8b440b92000ba0001cd21c3 }


condition:
	$a0
}