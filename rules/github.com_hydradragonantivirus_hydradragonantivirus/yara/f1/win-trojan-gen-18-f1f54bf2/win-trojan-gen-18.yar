rule Win_Trojan_Gen_18
{
strings:
	$a0 = { cd21fec0d0e03ad07533b413cd2f1e52b413cd2f5a1fb81325cd21b90100ba8005b80803cd13 }


condition:
	$a0
}