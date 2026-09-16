rule Win_Trojan_Delsys_5
{
strings:
	$a0 = { 64656c205c73797374656d33325c2a2e646c6c2064656c[0-17]6d5c2a2e646c6c }


condition:
	$a0
}