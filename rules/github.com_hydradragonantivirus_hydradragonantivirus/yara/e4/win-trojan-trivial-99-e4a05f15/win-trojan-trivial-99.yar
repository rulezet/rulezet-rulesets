rule Win_Trojan_Trivial_99
{
strings:
	$a0 = { 8a1e8000c687810000b8023dba8200cd219387f2b440cd21c3 }


condition:
	$a0
}