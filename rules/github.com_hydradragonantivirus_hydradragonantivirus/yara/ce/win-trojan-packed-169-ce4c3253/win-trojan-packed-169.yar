rule Win_Trojan_Packed_169
{
strings:
	$a0 = { 68646c6c0068696c742e68706e676654 }


condition:
	$a0
}