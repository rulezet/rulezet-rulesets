rule Win_Trojan_Pan_2
{
strings:
	$a0 = { e8020000d35b430e1f8a2783c31a90b9c903908a0732c48807fec443e2f5 }


condition:
	$a0
}