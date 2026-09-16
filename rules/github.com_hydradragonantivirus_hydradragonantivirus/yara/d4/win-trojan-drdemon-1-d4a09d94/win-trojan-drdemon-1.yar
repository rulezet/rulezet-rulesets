rule Win_Trojan_DrDemon_1
{
strings:
	$a0 = { f7065b83eb03501e0653fcb452cd214b4b268e1f5b0e0733f6ac505aadad1e8cde468ede33f68bfbb91000f3a65974 }


condition:
	$a0
}