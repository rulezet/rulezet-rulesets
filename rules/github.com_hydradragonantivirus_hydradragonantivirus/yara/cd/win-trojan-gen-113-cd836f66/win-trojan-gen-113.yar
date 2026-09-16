rule Win_Trojan_Gen_113
{
strings:
	$a0 = { be00008d842001508dbc2001b9500280050147497402ebf7c3 }


condition:
	$a0
}