rule Win_Trojan_Trivial_404
{
strings:
	$a0 = { b90700ba5701cd217246b8023dba9e00cd2193b440b1e1ba0001cd21b43ecd21b44febe2b42acd21 }


condition:
	$a0
}