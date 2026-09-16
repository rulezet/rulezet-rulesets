rule Win_Trojan_Clicker_60
{
strings:
	$a0 = { 4383fb050f8238ffffff8345fc58ff45f0817dfcc03040000f8c22ffffff8b1d002040008b3d04204000c745f402000000c745fc44304000 }


condition:
	$a0
}