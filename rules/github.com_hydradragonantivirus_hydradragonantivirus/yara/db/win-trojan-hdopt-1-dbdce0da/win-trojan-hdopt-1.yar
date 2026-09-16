rule Win_Trojan_HDOpt_1
{
strings:
	$a0 = { 551e50e8290a44445dc3558bec81ec5e0256573bec72063926351d72040ee8281533f6b8791e50 }


condition:
	$a0
}