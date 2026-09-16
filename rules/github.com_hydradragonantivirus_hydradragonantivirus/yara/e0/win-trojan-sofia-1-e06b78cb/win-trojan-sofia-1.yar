rule Win_Trojan_Sofia_1
{
strings:
	$a0 = { fc4b743b3dbebe741d3d0378751280ff19750d81ff4c }


condition:
	$a0
}