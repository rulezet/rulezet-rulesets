rule Win_Trojan_Bancos_1773
{
strings:
	$a0 = { 320735efba12a108f087247d080beed55978f876ea9c35345fe39f0d9fdcb9086cfaaf1aca58395d7dcbf137ed2f9ac8d44bb6a6cfe398fa1a0168c9adf56acf771c4e224141 }


condition:
	$a0
}