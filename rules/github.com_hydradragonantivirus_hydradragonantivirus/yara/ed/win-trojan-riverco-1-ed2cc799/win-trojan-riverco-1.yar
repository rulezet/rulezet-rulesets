rule Win_Trojan_Riverco_1
{
strings:
	$a0 = { ebd3fd14d5ebd379d33ad3d3fd5cd5ebd36b09e31ef2cdd55f0b9b5d0b6dd0d352ffa7d25025c252 }


condition:
	$a0
}