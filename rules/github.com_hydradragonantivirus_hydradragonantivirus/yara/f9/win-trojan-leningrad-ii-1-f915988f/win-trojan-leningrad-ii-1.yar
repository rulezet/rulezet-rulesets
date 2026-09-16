rule Win_Trojan_Leningrad_II_1
{
strings:
	$a0 = { 3e8801bebe7503e988000e07b44abbffffcd2181eb0301 }


condition:
	$a0
}