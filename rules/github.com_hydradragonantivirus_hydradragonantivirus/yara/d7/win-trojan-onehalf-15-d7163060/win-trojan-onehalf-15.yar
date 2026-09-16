rule Win_Trojan_OneHalf_15
{
strings:
	$a0 = { bc007c8ed38edb832e130404cd12b106d3e0ba80008ec0b90b00b8070206cd13b8d20050cb }


condition:
	$a0
}