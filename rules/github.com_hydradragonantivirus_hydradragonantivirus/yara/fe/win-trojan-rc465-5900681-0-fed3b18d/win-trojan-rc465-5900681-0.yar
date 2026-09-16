rule Win_Trojan_RC465_5900681_0
{
strings:
	$a0 = { b9c801000099f7f98a9495[4]8b45??8b4d??321408 }


condition:
	$a0
}