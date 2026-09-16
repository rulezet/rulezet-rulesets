rule Win_Trojan_Agent_35423
{
strings:
	$a0 = { 558bec83ec24535657c745fc0100 }

	$a1 = { 7a686d675a123543 }

	$a2 = { 703270693134 }

	$a3 = { 747261636b696430 }


condition:
	$a0 and $a1 and $a2 and $a3
}