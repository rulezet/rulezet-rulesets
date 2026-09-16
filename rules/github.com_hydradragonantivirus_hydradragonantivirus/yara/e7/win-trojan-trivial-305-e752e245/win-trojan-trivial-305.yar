rule Win_Trojan_Trivial_305
{
strings:
	$a0 = { b92000ba2f01cd217207e80600b44febf5cd20b8023dba9e00cd218bd8b440b9350090ba0001 }


condition:
	$a0
}