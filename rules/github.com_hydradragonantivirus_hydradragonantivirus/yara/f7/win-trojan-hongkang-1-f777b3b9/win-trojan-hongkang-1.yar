rule Win_Trojan_HongKang_1
{
strings:
	$a0 = { ffcd213d97197503e9c400b800008ed8bffe04813d97 }


condition:
	$a0
}