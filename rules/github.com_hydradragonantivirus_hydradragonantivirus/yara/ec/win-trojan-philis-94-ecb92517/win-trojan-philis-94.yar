rule Win_Trojan_Philis_94
{
strings:
	$a0 = { f7d1f7d1605633f6eb01eb5ee8000000006090be624a0000610f00e35ab8d80000000f00e003c2575081 }


condition:
	$a0
}