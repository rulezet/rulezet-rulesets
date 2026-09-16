rule Win_Trojan_Trivial_545
{
strings:
	$a0 = { b44eba????cd21b8013dba????cd2193b440b1??ba0001cd21c3 }


condition:
	$a0
}