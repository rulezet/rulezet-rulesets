rule Win_Trojan_Autumnal_1
{
strings:
	$a0 = { ffba8000bb00078bcf83c103b80102cd1381eb00024783 }


condition:
	$a0
}