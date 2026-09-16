rule Win_Trojan_Small_4253
{
strings:
	$a0 = { 8d3405000000008d743300[0-120]8145105c0900008d7d10 }


condition:
	$a0
}