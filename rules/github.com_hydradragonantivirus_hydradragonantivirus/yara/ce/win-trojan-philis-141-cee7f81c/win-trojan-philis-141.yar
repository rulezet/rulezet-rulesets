rule Win_Trojan_Philis_141
{
strings:
	$a0 = { 575783c404890424d3c85458588bc3e85002000000 }


condition:
	$a0
}