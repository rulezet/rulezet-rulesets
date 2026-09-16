rule Win_Trojan_Anomaly_1
{
strings:
	$a0 = { b43fb915018d960301fec4cd21b801573e8b8e3102 }


condition:
	$a0
}