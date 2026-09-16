rule Win_Trojan_Popuper_5
{
strings:
	$a0 = { 726d6469722022257322 }

	$a1 = { 3d3d3e5658585b62625a5f5f595757584e4c4a5255454e52494645483f3c463f3d2c2a2a }


condition:
	$a0 and $a1
}