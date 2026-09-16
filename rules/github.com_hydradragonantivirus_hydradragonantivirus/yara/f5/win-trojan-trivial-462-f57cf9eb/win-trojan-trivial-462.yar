rule Win_Trojan_Trivial_462
{
strings:
	$a0 = { f8f8b44eba3001cd21b8013dba9e00cd2193ba0001b15cb440cd21b43ecd21b44fcd2173e4b409ba3501cd21c3 }


condition:
	$a0
}