rule Win_Trojan_Father_1
{
strings:
	$a0 = { d705f3a433c08ed8e8fafec706840085018c068600c7069c006d018c069e00 }


condition:
	$a0
}