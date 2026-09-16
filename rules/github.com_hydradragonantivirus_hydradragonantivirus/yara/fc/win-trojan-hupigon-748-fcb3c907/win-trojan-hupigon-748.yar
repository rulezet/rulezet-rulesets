rule Win_Trojan_Hupigon_748
{
strings:
	$a0 = { d8bbfb2b9b3a1680c66ac936a4ee0e7309fff092ef7f2023908fb3da253d38d43733739178a83f67a4ee5aec86530840dad538a2ad12325fcb848f9983583b591aad14fe481aacad4410f7b93e95 }


condition:
	$a0
}