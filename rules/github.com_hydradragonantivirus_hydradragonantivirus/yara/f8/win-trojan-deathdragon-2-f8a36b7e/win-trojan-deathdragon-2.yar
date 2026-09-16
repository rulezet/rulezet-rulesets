rule Win_Trojan_DeathDragon_2
{
strings:
	$a0 = { e800005d81ed0601bf0001578db6ca02a5a48d96cd02b41acd218d96b402b44eb91b00cd217312e9a0005b4445415448 }


condition:
	$a0
}