rule Win_Trojan_Lineage_465
{
strings:
	$a0 = { e8d1d7ffffa1dca6400083780400751e6a00a150a6400050b8e8664000506a03e881d3ffff8b15dca64000 }


condition:
	$a0
}