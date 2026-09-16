rule Win_Trojan_Dreg_1
{
strings:
	$a0 = { 0400cc8d8e4606ffd1aae6273cd13cd90f334a8c0b144aac0a1444f64e940d1438e51ee51ee934ca48db34ca4f840a }


condition:
	$a0
}