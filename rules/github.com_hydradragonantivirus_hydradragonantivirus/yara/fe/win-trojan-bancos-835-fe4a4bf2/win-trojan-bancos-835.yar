rule Win_Trojan_Bancos_835
{
strings:
	$a0 = { 3d2d3d2d3d2d3d554e4942414e434f3d2d3d2d3d2d3d }


condition:
	$a0
}