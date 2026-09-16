rule Win_Trojan_Xak_1
{
strings:
	$a0 = { faa370008c067200fb8cc88ed8e92000b8ffffbb0200cd213b9cf1047d03e90c003b9cf104 }


condition:
	$a0
}