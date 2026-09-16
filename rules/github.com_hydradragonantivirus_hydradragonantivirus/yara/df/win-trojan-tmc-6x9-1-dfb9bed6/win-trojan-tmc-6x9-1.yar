rule Win_Trojan_TMC_6x9_1
{
strings:
	$a0 = { 8cd88986ee04488ed8a103003d00197303e93a040e1f8986ec048b9ee804b44acd21 }


condition:
	$a0
}