rule Win_Trojan_Dune_4
{
strings:
	$a0 = { 02b9a2002630460026004e0045e2f52e8b1e24022e8b }


condition:
	$a0
}