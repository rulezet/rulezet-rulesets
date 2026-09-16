rule Win_Trojan_QQShou_14
{
strings:
	$a0 = { f625becb8a47877b15aa75ab60c9ab6ef610220fdb095e914968aea8e73e184934c6cd02e0ab96c25006290cc2e8c28a91098e8a126a9a83c1cf97d9f206 }


condition:
	$a0
}