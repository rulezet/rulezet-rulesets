rule Win_Trojan_DarkElf_1
{
strings:
	$a0 = { 0e1f33dbb9ca008b84f1063020d0c4d0c402e0fec0d0c843e2f18984f106e90ff9 }


condition:
	$a0
}