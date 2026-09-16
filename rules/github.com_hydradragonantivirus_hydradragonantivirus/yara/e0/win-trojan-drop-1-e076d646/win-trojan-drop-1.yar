rule Win_Trojan_Drop_1
{
strings:
	$a0 = { ffcd213dff0175335e071f2e81bc45044d5a75108cc8 }


condition:
	$a0
}