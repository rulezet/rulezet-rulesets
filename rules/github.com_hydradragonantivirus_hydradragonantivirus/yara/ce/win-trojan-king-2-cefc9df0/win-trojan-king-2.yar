rule Win_Trojan_King_2
{
strings:
	$a0 = { e800005e83ee038ec0bf0002263a0575228ed8b3848b0fc707????43438b07c7071000890e }


condition:
	$a0
}