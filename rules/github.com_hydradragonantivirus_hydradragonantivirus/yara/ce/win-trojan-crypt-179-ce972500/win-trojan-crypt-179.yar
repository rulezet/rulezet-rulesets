rule Win_Trojan_Crypt_179
{
strings:
	$a0 = { f98bc260981bc6e805000000e906000000fc2bc7c30bc0f8c1e8c9e80a00000013c6e909000000482bc7c3a9ce42 }


condition:
	$a0
}