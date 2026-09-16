rule Win_Trojan_VGEN_587
{
strings:
	$a0 = { 03001e06cd2a3d000075298ec326813e0002bfe0741e8db60000bfe001b93901f3a48ed9be8400bf7002a5a5c7 }


condition:
	$a0
}