rule SecuDE_random_mult__32_lil_32_
{
strings:
	$a0 = { 75563412efcdab89150811474c3d2e1ffc4563255424bcfdacfb4523fb876afd }

condition:
	$a0
}