rule Win_Trojan_EVC_3
{
strings:
	$a0 = { 81c2847181c2f41481ea181c81f2f10bcd21b8c25b35b35035ca3f35cfc635e24b056c8833c9 }


condition:
	$a0
}