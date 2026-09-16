rule Win_Trojan_BPU_1
{
strings:
	$a0 = { 0d008bfc8d1e2200bc4000312043434c75f9cbe7c406 }


condition:
	$a0
}