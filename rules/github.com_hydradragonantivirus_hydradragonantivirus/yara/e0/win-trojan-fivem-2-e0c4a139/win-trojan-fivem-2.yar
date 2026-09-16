rule Win_Trojan_Fivem_2
{
strings:
	$a0 = { 7504b8ffffcf80fc3d740780fc4b7405eb06e98e00 }


condition:
	$a0
}