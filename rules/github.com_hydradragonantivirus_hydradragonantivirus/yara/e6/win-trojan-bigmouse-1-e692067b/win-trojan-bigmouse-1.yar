rule Win_Trojan_BigMouse_1
{
strings:
	$a0 = { 0e1fe800005eb9e00183c61190813411234646e2f8 }


condition:
	$a0
}