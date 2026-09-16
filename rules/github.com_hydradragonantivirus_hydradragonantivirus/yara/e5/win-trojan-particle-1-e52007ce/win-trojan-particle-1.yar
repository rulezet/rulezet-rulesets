rule Win_Trojan_Particle_1
{
strings:
	$a0 = { b63f018dbe5f01b94201313583c702e2f959c3e8e8ff }


condition:
	$a0
}