rule Win_Trojan_Trivial_340
{
strings:
	$a0 = { 023dba9e00cd218bd8b43fb101ba4301cd21803e4301b474e0b8004233c933d2cd21b440b143ba }


condition:
	$a0
}