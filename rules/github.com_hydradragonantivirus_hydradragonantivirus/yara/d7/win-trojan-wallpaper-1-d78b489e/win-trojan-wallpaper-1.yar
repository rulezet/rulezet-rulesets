rule Win_Trojan_WallPaper_1
{
strings:
	$a0 = { 020055a6000000000100090300004d1c0000040000004203 }


condition:
	$a0
}