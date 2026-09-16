rule Win_Trojan_Pixel_25
{
strings:
	$a0 = { 02b9ffffb43fcd2105e3022ea3110133c98bd12e8b1e1301b80042cd217211ba00002e8b0e11 }


condition:
	$a0
}