rule Win_Trojan_Bancos_1488
{
strings:
	$a0 = { ee77b19bc0e07a46b40731627e290ce65d00d709ccf16869ca255585e356fb72570e1adf6e58568f8eb4d9e425dc6b0c8a483972958af46df332f17141dccf7ef8ef2cecefddad2759e5cba5d2d1640b20c4 }


condition:
	$a0
}