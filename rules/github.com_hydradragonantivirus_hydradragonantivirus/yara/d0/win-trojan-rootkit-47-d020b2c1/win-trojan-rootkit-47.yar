rule Win_Trojan_Rootkit_47
{
strings:
	$a0 = { 55bd????0100ffd5005dc20800001400 }


condition:
	$a0
}