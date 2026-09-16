rule Win_Trojan_VB_1024
{
strings:
	$a0 = { 68f01b4000e8f0ffffff0000000000003000000040 }

	$a1 = { 5359533939 }

	$a2 = { 6f006e005c00520075006e }

	$a3 = { 4700450054 }


condition:
	$a0 and $a1 and $a2 and $a3
}