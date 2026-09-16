rule Win_Trojan_Breath_1
{
strings:
	$a0 = { 45d3d3d0d3f881cb0100d3d301db83eb34bb1000039d2901d3d319c383d345bb1000434319c331db01db19c339e4 }


condition:
	$a0
}