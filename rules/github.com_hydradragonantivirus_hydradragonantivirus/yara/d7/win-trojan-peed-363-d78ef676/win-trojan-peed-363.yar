rule Win_Trojan_Peed_363
{
strings:
	$a0 = { 83c70583ff05741f81ff4fb400007f17b9 }


condition:
	$a0
}