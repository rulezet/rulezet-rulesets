rule Win_Trojan_Riot_31
{
strings:
	$a0 = { 2acd2180fa15740ab409ba2b02cd21eb1290b409babf01cd21b9e803b8070ecd10e2fce91e019c80fc4b7402eb39b8014380e1fecd21b8023dcd218bd85053 }


condition:
	$a0
}