rule Win_Trojan_Moran_1
{
strings:
	$a0 = { 09310c31144649420bc975f5c3908bdc36c44706fa33 }


condition:
	$a0
}