rule Win_Trojan_VGEN_266
{
strings:
	$a0 = { 042d0200a31304b106d3e02d60008ec08bf4bf0006b90001f3a5ba77060652cb33c022d0cd13 }


condition:
	$a0
}