rule Win_Trojan_Y_6
{
strings:
	$a0 = { 90900e07be0401b91401fcb81e1ecd218ec3bf0002f3a48edbbe8400a5a5c744fc4f02894cfeebda204d616c6172 }


condition:
	$a0
}