rule Win_Trojan_W13_1
{
strings:
	$a0 = { 8bd72bf983c70205030103c18905b440 }


condition:
	$a0
}