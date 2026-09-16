rule Win_Trojan_Zbot_1217
{
strings:
	$a0 = { c1c204b85cfcaf82c1c005c1ce15ba90ffffff21e989e6b90000000001ff668b }


condition:
	$a0
}