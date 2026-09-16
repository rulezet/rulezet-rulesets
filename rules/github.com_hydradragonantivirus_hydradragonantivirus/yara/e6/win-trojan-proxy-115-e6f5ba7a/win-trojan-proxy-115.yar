rule Win_Trojan_Proxy_115
{
strings:
	$a0 = { e81609962de91608cebecccccccc518d4c24042bc81bc0f7d023 }

	$a1 = { 2a2f2a00504f5354 }


condition:
	$a0 and $a1
}