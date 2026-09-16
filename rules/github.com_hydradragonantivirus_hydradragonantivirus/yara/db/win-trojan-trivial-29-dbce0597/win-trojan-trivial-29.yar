rule Win_Trojan_Trivial_29
{
strings:
	$a0 = { 01c3b443b000ba9e00cd21b443b001ba9e00b100cd21b8013dba9e00cd2193b440b13cba00 }


condition:
	$a0
}