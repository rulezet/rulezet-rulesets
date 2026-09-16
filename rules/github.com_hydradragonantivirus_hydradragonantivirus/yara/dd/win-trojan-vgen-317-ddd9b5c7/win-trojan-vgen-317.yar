rule Win_Trojan_VGEN_317
{
strings:
	$a0 = { 8bdfbebb01adabacaa83c404588bc350c30084a0ada8abaea2202d20abaee521204472576562202d20a3aee0a1 }


condition:
	$a0
}