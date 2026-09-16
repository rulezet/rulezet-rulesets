rule Win_Trojan_AntiTrace_2
{
strings:
	$a0 = { 525657e800005b81eb0800b8dec0cd213dbaba1e06747c8cc0488ec0b25a26803e00005a7402b24d26c60600004d }


condition:
	$a0
}