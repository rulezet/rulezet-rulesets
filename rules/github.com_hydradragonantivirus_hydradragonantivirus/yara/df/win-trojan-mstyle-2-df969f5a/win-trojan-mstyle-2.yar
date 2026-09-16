rule Win_Trojan_Mstyle_2
{
strings:
	$a0 = { 09e6d7dd0d61fef379db5685a2a9563100f66bb3392462ab552e4871869c }


condition:
	$a0
}