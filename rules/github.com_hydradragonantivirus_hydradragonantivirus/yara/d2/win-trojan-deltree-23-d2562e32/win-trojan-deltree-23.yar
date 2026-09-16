rule Win_Trojan_Deltree_23
{
strings:
	$a0 = { 44454c5452454500132f7920433a5c50726f6772617e315c2a2e2a }


condition:
	$a0
}