rule Win_Adware_MultiPlug_2
{
strings:
	$a0 = { 000000005b636f6e666967446174615d00 }

	$a1 = { 0037623232 }

	$a2 = { 32323764005b636f6e666967446174615d00 }


condition:
	$a0 and $a1 and $a2
}