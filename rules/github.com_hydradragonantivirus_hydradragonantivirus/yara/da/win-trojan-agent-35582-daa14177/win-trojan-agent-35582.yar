rule Win_Trojan_Agent_35582
{
strings:
	$a0 = { 1b3f47edc2cbe2de9c28dd1c7a1417bdf56ded907417cd41ea5c07b5019e6782 }


condition:
	$a0
}