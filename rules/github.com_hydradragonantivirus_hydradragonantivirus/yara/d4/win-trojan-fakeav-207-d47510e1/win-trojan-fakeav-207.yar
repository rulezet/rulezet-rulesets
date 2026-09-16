rule Win_Trojan_FakeAV_207
{
strings:
	$a0 = { 7368656c6c5c6f70656e5c636f6d6d616e643d686a766a74652e657865 }


condition:
	$a0
}