rule Win_Trojan_Gremlin_3
{
strings:
	$a0 = { b8aad5cd213d032a745f908bc44090b1 }


condition:
	$a0
}