rule Win_Trojan_VLAD_19
{
strings:
	$a0 = { 5d81ed06018db6e402bf0001a5a4c686310300b44732d28db6f102cd21b41a8d963203cd21b44eb90700fe8eea028d }


condition:
	$a0
}