rule Win_Trojan_Trivial_123
{
strings:
	$a0 = { 4eba1801cd21b8023dba9e00cd2193b440ba0001cd21cc2a2e2a }


condition:
	$a0
}