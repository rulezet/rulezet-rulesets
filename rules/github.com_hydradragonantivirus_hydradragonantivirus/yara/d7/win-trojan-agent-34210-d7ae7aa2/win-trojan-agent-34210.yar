rule Win_Trojan_Agent_34210
{
strings:
	$a0 = { 909090b8????????ffe090900000000000000000000000000000000000000000 }


condition:
	$a0
}