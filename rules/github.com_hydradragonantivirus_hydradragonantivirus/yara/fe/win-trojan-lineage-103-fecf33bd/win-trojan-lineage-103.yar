rule Win_Trojan_Lineage_103
{
strings:
	$a0 = { 5bac332c7f9381ab46db7032bb029aec840e9771073d641f907b7ca5c5a26447583f908c9156b1ed77afa4eadf18d2dfb73a71b9f3ef8b721b859a588805251f1bfa53c1 }


condition:
	$a0
}