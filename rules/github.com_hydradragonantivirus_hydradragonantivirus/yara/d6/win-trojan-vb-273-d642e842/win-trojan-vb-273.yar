rule Win_Trojan_VB_273
{
strings:
	$a0 = { c745d478264000c745cc08000000ff15e01040008d55dc6a0252ff1588104000 }


condition:
	$a0
}