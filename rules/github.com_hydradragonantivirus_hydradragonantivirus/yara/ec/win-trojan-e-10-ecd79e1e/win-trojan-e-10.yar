rule Win_Trojan_E_10
{
strings:
	$a0 = { 5dfa4490050e6d5dbc7c36212c2a2bc2047a48bbf6c4fb7b88d1232224b45dfa4436210eb05df804 }


condition:
	$a0
}