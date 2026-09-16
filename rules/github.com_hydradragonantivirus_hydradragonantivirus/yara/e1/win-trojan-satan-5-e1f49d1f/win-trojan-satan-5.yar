rule Win_Trojan_Satan_5
{
strings:
	$a0 = { e80000fa0e1f8bec836e00035ebb2400b9e90e2bcb823064fe0843e2f8b8680103c650c3 }


condition:
	$a0
}