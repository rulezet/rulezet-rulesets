rule Win_Trojan_Timishoara_1
{
strings:
	$a0 = { 06005e33ff0e1fb95408fcf3a406b8780050cb0e1fe85205 }


condition:
	$a0
}