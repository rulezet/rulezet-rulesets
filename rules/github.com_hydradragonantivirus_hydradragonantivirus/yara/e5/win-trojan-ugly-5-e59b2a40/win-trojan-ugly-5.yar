rule Win_Trojan_Ugly_5
{
strings:
	$a0 = { b99017bb0f012e80370043e2f990bd0001b91b0132c0bf9f1703fd0e07fcf3aafa0e17bc4a1a03e589aeb9028c9ecf }


condition:
	$a0
}