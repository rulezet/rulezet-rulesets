rule Win_Trojan_X_7
{
strings:
	$a0 = { 5e813c4d5a8bd58ec575158bfcb80272508b44148b74168d7210568bf050eb13bf0001b91800 }


condition:
	$a0
}