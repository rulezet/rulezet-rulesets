rule Win_Trojan_Mithrandir_4
{
strings:
	$a0 = { 753b9d5f0726817d034459752683ef0bfc061f5657 }


condition:
	$a0
}