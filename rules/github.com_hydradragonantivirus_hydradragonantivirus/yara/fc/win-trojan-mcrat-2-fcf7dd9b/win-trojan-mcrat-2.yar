rule Win_Trojan_McRat_2
{
strings:
	$a0 = { ff75088b35c02000108d85f0fdffff50ffd685c0741f8d85ccfdffff50ff75f8e81a08000085c07447ff75088d85f0fdffff50ebdb8b85d4fdffff506a0068ff0f1f008945fcff15c8200010 }


condition:
	$a0
}