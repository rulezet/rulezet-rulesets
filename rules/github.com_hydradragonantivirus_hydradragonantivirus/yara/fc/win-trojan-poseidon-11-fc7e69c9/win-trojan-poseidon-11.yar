rule Win_Trojan_Poseidon_11
{
strings:
	$a0 = { 558becb83c110000e8933a01008b4508535657a324d64200 }

	$a1 = { 8b6d14ffd55f5e5b8be55dc21000 }


condition:
	$a0 and $a1
}