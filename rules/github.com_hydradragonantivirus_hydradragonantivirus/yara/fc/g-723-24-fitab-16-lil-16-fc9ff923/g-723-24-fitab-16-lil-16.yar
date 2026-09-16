rule G_723_24__fitab__16_lil_16_
{
strings:
	$a0 = { 000000020004000e000e000400020000 }

condition:
	$a0
}