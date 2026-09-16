rule Win_Trojan_Bancos_1883
{
strings:
	$a0 = { 26cc2fba5c3e52c2fd9b110f1e5f2f6704235d43a26a9e9c59895e3c3a043ad7b0130a1156b589d37c8c78c1a8b240711a760c9b5dace87504e33988bc3b70af51cab008be77 }


condition:
	$a0
}