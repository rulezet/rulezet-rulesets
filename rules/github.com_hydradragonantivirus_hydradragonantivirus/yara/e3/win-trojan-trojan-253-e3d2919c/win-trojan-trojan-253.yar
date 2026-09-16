rule Win_Trojan_Trojan_253
{
strings:
	$a0 = { b99f02402e300446e2f9c3 }


condition:
	$a0
}