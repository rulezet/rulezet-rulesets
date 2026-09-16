rule Win_Dropper_Agent_35605
{
strings:
	$a0 = { 6834cb05dfe8179b01006837cb0597e80897010041b302 }

	$a1 = { 75780d323262273f7c5c05[0-72]1b58087632b7a51f }


condition:
	$a0 and $a1
}