rule Win_Trojan_VGEN_580
{
strings:
	$a0 = { 015756b90300f3a45f5e575e83ee03061eba60008ec233ffb9a6009026803de8741e57f3a41fbe8400a5a50e1f }


condition:
	$a0
}