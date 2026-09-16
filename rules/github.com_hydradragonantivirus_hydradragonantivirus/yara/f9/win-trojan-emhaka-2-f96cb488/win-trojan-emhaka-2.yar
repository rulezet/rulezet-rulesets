rule Win_Trojan_Emhaka_2
{
strings:
	$a0 = { 535152061e9cfae800005f89e5be290081c73501804e01010e575631f68ede5f8f44048f44069dfbe92e02c3e596ab }


condition:
	$a0
}