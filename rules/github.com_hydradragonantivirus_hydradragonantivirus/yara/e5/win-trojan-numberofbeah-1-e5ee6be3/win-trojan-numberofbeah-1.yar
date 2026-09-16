rule Win_Trojan_NumberofBeaH_1
{
strings:
	$a0 = { 30cd2186e03d1e03beb407730abea5103c0a7403bec91e8ed9bff800a5a5be8400a5a5c544fc0657be0800b501f3a70e1f744ab452cd2106bef8002bff26c4 }


condition:
	$a0
}