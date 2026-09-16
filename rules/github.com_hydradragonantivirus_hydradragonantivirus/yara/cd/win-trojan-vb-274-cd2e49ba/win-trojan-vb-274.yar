rule Win_Trojan_VB_274
{
strings:
	$a0 = { c745d4d42d4000c745cc08000000ff15041140008d55dc6a0252ff15a01040008d4ddcddd8ff1510104000 }


condition:
	$a0
}