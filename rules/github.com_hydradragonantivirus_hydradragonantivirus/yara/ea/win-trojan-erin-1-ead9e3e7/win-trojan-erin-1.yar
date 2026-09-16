rule Win_Trojan_Erin_1
{
strings:
	$a0 = { 81ed0601b9ffffeb0690b8004ccd21e2f6b903008db6d501bf000157f3a48d96db01b41acd21b44e8d96cf01b90700 }


condition:
	$a0
}