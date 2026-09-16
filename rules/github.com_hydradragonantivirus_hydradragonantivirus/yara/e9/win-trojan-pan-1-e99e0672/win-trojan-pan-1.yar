rule Win_Trojan_Pan_1
{
strings:
	$a0 = { e80200007a5b0e431f8a2783c31a90b9c903908a0732c4880743fec4e2f5 }


condition:
	$a0
}