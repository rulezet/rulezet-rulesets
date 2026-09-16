rule Win_Trojan_Palma_2
{
strings:
	$a0 = { d581c20401b9cf01cd212e8f45022e8f05b43ecd21 }


condition:
	$a0
}