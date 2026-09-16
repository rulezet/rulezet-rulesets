rule Win_Trojan_Monster_51
{
strings:
	$a0 = { 8a440ca200018b440da30101b82425baa10103d6cd21 }


condition:
	$a0
}