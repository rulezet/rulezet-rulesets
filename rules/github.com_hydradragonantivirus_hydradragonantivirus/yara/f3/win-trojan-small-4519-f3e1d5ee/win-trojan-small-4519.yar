rule Win_Trojan_Small_4519
{
strings:
	$a0 = { b821dae50f2d2164a50f5050e8??0000 }


condition:
	$a0
}