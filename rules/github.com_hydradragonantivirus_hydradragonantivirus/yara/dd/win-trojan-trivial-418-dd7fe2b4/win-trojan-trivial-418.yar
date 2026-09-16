rule Win_Trojan_Trivial_418
{
strings:
	$a0 = { 4eba2301cd217216ba9e00b8023dcd2193b440ba0001b131cd21b44febe6b44ccd21 }


condition:
	$a0
}