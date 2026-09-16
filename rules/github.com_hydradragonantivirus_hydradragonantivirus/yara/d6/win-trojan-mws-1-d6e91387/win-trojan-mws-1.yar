rule Win_Trojan_MWS_1
{
strings:
	$a0 = { 1e3001b440e897ffc3b0008b163a014ab90000e8d5ff721ab901008d163201e8d3ff720ea02304 }


condition:
	$a0
}