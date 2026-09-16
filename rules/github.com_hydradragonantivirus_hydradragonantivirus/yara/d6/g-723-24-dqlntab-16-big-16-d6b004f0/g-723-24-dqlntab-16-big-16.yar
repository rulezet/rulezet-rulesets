rule G_723_24__dqlntab__16_big_16_
{
strings:
	$a0 = { F800008701110175017501110087F800 }

condition:
	$a0
}