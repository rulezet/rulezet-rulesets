rule Win_Trojan_Zhugeliang_3
{
strings:
	$a0 = { fec24ac6060c01ca16bad5be5ab1e181f6c8ed8acccd6a3db2c2b1c583f61189f2068bf08fc20689f68fc234b232 }


condition:
	$a0
}