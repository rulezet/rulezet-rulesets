rule Win_Trojan_SillyC_239
{
strings:
	$a0 = { 2a2e636f6d005589e58b56041e8e5e06b41acd211f5dc204 }


condition:
	$a0
}