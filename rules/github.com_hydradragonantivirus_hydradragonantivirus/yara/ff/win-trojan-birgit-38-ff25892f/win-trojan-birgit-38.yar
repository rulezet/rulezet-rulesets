rule Win_Trojan_Birgit_38
{
strings:
	$a0 = { 01b97e012e8ab6aa022e8a2732e62e882743e2f5c3 }


condition:
	$a0
}