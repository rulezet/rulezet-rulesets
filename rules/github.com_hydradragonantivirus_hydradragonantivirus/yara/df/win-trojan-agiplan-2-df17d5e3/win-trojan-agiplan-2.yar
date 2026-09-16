rule Win_Trojan_Agiplan_2
{
strings:
	$a0 = { 2575f9ba0042263b550175f0b6ba263a75fb75e883f900 }


condition:
	$a0
}