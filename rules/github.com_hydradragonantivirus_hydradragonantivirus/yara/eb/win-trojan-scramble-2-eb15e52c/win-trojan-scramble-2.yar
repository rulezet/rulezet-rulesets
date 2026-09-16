rule Win_Trojan_Scramble_2
{
strings:
	$a0 = { 75732020202020203d3d3d3d3d3d3d3d2d2d2d2d2d0d0a008db62000b85e01ffd08db64400 }


condition:
	$a0
}