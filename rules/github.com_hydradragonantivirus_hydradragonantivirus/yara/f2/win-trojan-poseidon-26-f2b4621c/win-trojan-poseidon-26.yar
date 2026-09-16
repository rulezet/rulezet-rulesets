rule Win_Trojan_Poseidon_26
{
strings:
	$a0 = { 558bec83e4f8b8ec2f0000e8b1640000a17cb0420033c4898424e82f00008b45 }

	$a1 = { 53ffb424a40000005353ff15bca14100e963010000 }

	$a2 = { 8b8c24f42f00005f5e5b33cce84f0400008be55dc21000 }


condition:
	$a0 and $a1 and $a2
}