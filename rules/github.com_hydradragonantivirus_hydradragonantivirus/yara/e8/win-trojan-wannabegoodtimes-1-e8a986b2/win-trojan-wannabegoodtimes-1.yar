rule Win_Trojan_WannaBeGoodTimes_1
{
strings:
	$a0 = { 75034444cf5351525657551e0689d6fcac3c2e75fb }


condition:
	$a0
}