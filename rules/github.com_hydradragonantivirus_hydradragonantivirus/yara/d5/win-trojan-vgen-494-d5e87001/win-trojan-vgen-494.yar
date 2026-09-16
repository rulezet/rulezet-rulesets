rule Win_Trojan_VGEN_494
{
strings:
	$a0 = { 118cc82d10008ed8b013baba05e8290c071fcd1980fc01750c81fead0b750681ffcefa740680 }


condition:
	$a0
}