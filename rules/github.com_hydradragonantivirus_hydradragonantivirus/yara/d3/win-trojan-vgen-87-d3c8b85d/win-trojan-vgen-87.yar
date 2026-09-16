rule Win_Trojan_VGEN_87
{
strings:
	$a0 = { b3005589e531c09a7c02b300e8cfff5d31c09ae900b300558bec83ec501ec5760c8d7eb01607fcac3c4f7202b0 }


condition:
	$a0
}