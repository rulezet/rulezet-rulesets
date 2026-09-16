rule Win_Trojan_RedArc_3
{
strings:
	$a0 = { e800001e07975d83ed06bb0011b44acd217306071f610e56cbb8060203c5b104d3e8401e5b03c350 }


condition:
	$a0
}