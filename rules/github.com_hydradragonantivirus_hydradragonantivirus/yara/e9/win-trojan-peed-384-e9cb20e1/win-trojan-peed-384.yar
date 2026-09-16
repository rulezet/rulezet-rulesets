rule Win_Trojan_Peed_384
{
strings:
	$a0 = { 01f8054e1500003d4e15000074733d21cc00007f }


condition:
	$a0
}