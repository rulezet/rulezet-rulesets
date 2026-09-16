rule Win_Trojan_Dir_8
{
strings:
	$a0 = { 13f6c101741381e1fe00ba7003b801430e1fcd217303 }


condition:
	$a0
}