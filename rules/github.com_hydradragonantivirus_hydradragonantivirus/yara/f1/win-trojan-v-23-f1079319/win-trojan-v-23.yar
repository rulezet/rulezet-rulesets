rule Win_Trojan_V_23
{
strings:
	$a0 = { 8ed84033f6894401803c5a75088cc0488ed8c6045a06e8 }


condition:
	$a0
}