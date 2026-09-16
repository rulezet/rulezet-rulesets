rule Win_Trojan_Ultimate_1
{
strings:
	$a0 = { 1d5e5f894deb14ed6017725e51021278ebf401602b7f461f5e127818de5e2b7f911ee936e926e92e }


condition:
	$a0
}