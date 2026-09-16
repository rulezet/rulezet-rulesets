rule Win_Trojan_Overkill_1
{
strings:
	$a0 = { 2401866ee81500bfd8feb97e0481351f15ff0e1101471dfdeb0bebf1f7160a01f7169292c3e5e3a608872925088b }


condition:
	$a0
}