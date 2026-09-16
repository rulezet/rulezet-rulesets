rule Win_Trojan_Path_3
{
strings:
	$a0 = { 8a0d2ed20f5943e2eeeb1dbb1a01e866ff03ddb9f603 }


condition:
	$a0
}