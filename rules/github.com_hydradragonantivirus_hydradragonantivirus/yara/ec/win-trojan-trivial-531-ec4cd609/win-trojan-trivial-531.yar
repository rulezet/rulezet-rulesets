rule Win_Trojan_Trivial_531
{
strings:
	$a0 = { b8013dba????cd2193b440b9????ba0001cd21b409 }


condition:
	$a0
}