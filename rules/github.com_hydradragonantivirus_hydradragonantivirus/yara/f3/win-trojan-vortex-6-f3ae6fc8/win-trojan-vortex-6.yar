rule Win_Trojan_Vortex_6
{
strings:
	$a0 = { 2192909280fa0775ee929092b500b405b600929092b280cd13fec592909280fd20e0eb0d02 }


condition:
	$a0
}