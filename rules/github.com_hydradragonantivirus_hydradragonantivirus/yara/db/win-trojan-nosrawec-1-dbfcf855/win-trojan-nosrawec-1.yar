rule Win_Trojan_Nosrawec_1
{
strings:
	$a0 = { 5dc3ffffffff010000000a000000ffffffff0300000039387c00ffffffff010000007c000000ffffffff010000005c0000006f70656e00000000ffffffff1d00000033337c4b65796c6f }


condition:
	$a0
}