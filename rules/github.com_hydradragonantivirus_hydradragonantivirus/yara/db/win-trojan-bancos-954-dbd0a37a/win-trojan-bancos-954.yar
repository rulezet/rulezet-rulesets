rule Win_Trojan_Bancos_954
{
strings:
	$a0 = { 6e92d1e7f83ab31ecfc0dc0bfa358cd8de8bc1615bd19c7ed6b6a3881b23056fe41d264f222a0cef5fba309978ae9d3c69f39ddeaef6d404b72d9bcf2275093fef33a3555f0d40deaeaabd0cd261 }


condition:
	$a0
}