rule Win_Dropper_Agent_35586
{
strings:
	$a0 = { b800c04100ffe008ad251668875c380fdf4c780fdf4c780f }

	$a1 = { 4845787472656d616e74654d6f6e7374726f }


condition:
	$a0 and $a1
}