rule Win_Trojan_Small_231_1
{
strings:
	$a0 = { 542470516a006a006a006a016a006a006a0052ff150c30e179 }


condition:
	$a0
}