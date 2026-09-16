rule Win_Trojan_Duran_1
{
strings:
	$a0 = { 0103bb0002b90200ba8000890e780089167b00cd137214b80103bb0000b90100 }


condition:
	$a0
}