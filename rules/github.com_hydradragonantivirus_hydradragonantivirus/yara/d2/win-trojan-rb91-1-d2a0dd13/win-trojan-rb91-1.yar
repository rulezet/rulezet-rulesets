rule Win_Trojan_Rb91_1
{
strings:
	$a0 = { 010011f80f3c2d3d3d3d3d2d3e3c2d204c696e65204e6f203031202d3e3c2d204c696e65204e6f203032202d3e }


condition:
	$a0
}