rule Win_Trojan_Tanya_4
{
strings:
	$a0 = { e800005bfc83eb030e8eeb1fbe0000b9ee0266b8c61d05006601402b66c1c80c6635c43ea20583c6 }


condition:
	$a0
}