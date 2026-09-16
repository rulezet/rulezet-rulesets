rule Win_Trojan_Cop_1
{
strings:
	$a0 = { a19600251f003d1f007504b44febe7b8023dba9e00cd2193b80057cd215152b440ba0001b9 }


condition:
	$a0
}