rule Win_Trojan_Vgen_3
{
strings:
	$a0 = { ee03b87042cd213d77777502eb62e80705290602008b2e02008cda2bea06b44abbffffcd21b44acd214a8edaa103 }


condition:
	$a0
}