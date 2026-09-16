rule Win_Spyware_Banker_5879
{
strings:
	$a0 = { 0b62da16592fcdc6cfa15c78a8d82dc7ca944d0a8d5c31a13c652d34a5fa542093c39c9958d6148c4528beb970ab5a8f6b18be1db0901b55526401b3ed714879e3bc1a06 }


condition:
	$a0
}