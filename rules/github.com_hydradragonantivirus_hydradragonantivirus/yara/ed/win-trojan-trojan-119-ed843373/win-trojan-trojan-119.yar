rule Win_Trojan_Trojan_119
{
strings:
	$a0 = { fbcd210ae4742933c05007be0001bf0002b9c300f3a5061fbf8603be8400bb }


condition:
	$a0
}