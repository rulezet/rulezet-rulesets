rule Win_Trojan_CivilWar_19
{
strings:
	$a0 = { a07505b803009dcf505351521e0657545580fc3d7414 }


condition:
	$a0
}