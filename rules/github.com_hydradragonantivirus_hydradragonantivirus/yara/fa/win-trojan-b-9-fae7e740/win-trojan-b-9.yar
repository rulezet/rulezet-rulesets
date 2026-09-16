rule Win_Trojan_B_9
{
strings:
	$a0 = { 1c80fa80750488160b02fcb9a001be1e00bf1e02f3a4b80103419cff1e07 }


condition:
	$a0
}