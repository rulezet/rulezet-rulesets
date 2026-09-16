rule Win_Trojan_Suomi_1
{
strings:
	$a0 = { a80390eb039011008b87ee03eb02901e81c34400eb }


condition:
	$a0
}