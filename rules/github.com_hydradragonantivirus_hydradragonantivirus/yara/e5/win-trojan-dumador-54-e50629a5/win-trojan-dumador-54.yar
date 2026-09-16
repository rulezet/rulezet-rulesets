rule Win_Trojan_Dumador_54
{
strings:
	$a0 = { 4785df01c78d3df0c912a6f6d70fbffb69c23ba9e254157daabb5689db0fc0f4f7c730229478f7d389d8c7c0283427ab88de }


condition:
	$a0
}