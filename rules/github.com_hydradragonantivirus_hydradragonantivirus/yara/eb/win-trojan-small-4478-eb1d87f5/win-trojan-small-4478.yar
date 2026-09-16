rule Win_Trojan_Small_4478
{
strings:
	$a0 = { ff74241c588d80??????04506862343504e846000000508d1559??????525051 }


condition:
	$a0
}