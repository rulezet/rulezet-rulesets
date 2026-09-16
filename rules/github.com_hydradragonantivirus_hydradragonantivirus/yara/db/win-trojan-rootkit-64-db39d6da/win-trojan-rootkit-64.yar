rule Win_Trojan_Rootkit_64
{
strings:
	$a0 = { 68b4150100e818000000c7042420120100ff151c20010033c0c20800ccccccccccccff250820 }


condition:
	$a0
}