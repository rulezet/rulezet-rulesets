rule Win_Trojan_Stoned_35
{
strings:
	$a0 = { bb0002b80103cd1372e1b94202bfbe01bebe03f3a4ba8000b90100bb0000b80103cd13ebc6 }


condition:
	$a0
}