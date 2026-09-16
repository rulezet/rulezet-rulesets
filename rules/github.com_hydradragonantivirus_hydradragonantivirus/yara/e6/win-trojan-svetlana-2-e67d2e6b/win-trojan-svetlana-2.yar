rule Win_Trojan_Svetlana_2
{
strings:
	$a0 = { b440e8d0fc72253d0c08752033c933d2b80042e8bffc7214badc07b440b91800e8b2fc7207 }


condition:
	$a0
}