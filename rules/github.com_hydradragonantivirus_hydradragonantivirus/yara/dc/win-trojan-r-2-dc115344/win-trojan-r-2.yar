rule Win_Trojan_R_2
{
strings:
	$a0 = { e904007403e9d900833ef004017c0a7f0b813eee04a0867303e9c500bf7e040e57bff2041e57 }


condition:
	$a0
}