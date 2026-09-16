rule Win_Trojan_DeadFace_1
{
strings:
	$a0 = { bf007c8ed38be736a11304b10648d3e050500753ba0001b90f00b80102cd1372f9cb }


condition:
	$a0
}