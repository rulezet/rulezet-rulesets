rule Win_Trojan_Mis_1
{
strings:
	$a0 = { 5c5f2e657865c8040300c686fefe009a1b071e0109c07e619a1b071e018886fdfeb0013a86fd }


condition:
	$a0
}