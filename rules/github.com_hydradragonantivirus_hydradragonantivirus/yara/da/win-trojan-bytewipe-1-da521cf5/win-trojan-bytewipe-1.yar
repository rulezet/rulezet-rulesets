rule Win_Trojan_ByteWipe_1
{
strings:
	$a0 = { cd212d03002d0c002da8048bc85a5b585b2ec707e9002e884f012e886f022ec7470343002ec7 }


condition:
	$a0
}