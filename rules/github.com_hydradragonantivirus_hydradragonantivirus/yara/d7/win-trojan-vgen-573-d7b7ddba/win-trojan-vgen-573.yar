rule Win_Trojan_VGEN_573
{
strings:
	$a0 = { 8cc88ed0bcfefffbe80000545d8b46008346000f2d2601505dc306060e0e1f07c686a501008db6 }


condition:
	$a0
}