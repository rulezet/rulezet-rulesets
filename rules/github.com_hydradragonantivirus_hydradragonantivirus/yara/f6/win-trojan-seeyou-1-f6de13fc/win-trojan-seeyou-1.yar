rule Win_Trojan_SeeYou_1
{
strings:
	$a0 = { 33c08ed0bc007cbb130436832f02cd12b106d3e0508ec0ba0000b90100e54032e4508bd8b80102 }


condition:
	$a0
}