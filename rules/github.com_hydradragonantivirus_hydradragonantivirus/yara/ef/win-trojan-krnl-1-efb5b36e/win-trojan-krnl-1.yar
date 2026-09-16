rule Win_Trojan_Krnl_1
{
strings:
	$a0 = { d8eb039072728ec08d063200eb0290720510258bf08bf8eb03907272b9ec07ac0472aae2fa }


condition:
	$a0
}