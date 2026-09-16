rule Win_Trojan_Jerusalem_35
{
strings:
	$a0 = { cd218cc80510008ed0bc000750b8c5 }


condition:
	$a0
}