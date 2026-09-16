rule Win_Trojan_Poseidon_22
{
strings:
	$a0 = { 558bec83e4f8b8ac4b0000e856580000a11c50410033c4898424a84b00008b45 }

	$a1 = { 8b8c24b44b00005f5e5b33cce85a0600008be55dc21000 }

	$a2 = { 53ff7424205353ff15ccc14000 }


condition:
	$a0 and $a1 and $a2
}