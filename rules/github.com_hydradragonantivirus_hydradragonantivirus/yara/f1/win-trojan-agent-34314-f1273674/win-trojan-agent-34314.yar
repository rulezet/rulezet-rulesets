rule Win_Trojan_Agent_34314
{
strings:
	$a0 = { 87da45eb027a626083c4204d87da6a006087e85283ecfc87e861810424da1937 }


condition:
	$a0
}