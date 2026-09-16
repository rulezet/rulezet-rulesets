rule Win_Trojan_LaDiosa_1
{
strings:
	$a0 = { e800008bf4368b2c81ed0400fa83c402fb1f8cd88ec01e0668283a58cd213d293b7454b82035fec0 }


condition:
	$a0
}