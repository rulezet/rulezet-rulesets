rule Win_Trojan_VGEN_90
{
strings:
	$a0 = { 0500108ec0fe060401be010133ffb92701f3a4ba0501b906b44ecd21727254ba9ea501010101018bd8061fba27 }


condition:
	$a0
}