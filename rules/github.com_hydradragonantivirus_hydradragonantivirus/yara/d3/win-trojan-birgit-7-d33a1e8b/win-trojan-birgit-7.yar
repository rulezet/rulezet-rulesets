rule Win_Trojan_Birgit_7
{
strings:
	$a0 = { e80000cc8bfc368b2d81ed110183c40260b42acd2180fa127507b9ffffb002cd2661e805 }


condition:
	$a0
}