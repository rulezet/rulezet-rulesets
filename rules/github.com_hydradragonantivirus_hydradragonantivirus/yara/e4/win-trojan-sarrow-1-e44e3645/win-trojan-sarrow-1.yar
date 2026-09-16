rule Win_Trojan_Sarrow_1
{
strings:
	$a0 = { 5365636f6e644172726f77 }

	$a1 = { 282287fcfd4f87fc4454c3222c3029 }

	$a2 = { 3d2e686c70 }

	$a3 = { 426c75654f776c }


condition:
	$a0 and $a1 and $a2 and $a3
}