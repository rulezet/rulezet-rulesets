rule Win_Trojan_V_59
{
strings:
	$a0 = { cd2186c43d1e03beb407730abea5103c0a7403bec91e8ed9bff800a5a5be8400a5a5c544fc0657be0800b501f3a70e1f744ab452cd2106bef8002bff26c4 }


condition:
	$a0
}