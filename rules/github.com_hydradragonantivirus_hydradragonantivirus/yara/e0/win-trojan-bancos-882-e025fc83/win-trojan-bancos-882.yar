rule Win_Trojan_Bancos_882
{
strings:
	$a0 = { e9088a24c7df7ca5527fe4a709f3097f449a8b91705881361ae8a566f13c4fa284349eee197a5493fc5e527b4208d5418cefd3764cfeaf88764d243cc2a15f5f7d }


condition:
	$a0
}