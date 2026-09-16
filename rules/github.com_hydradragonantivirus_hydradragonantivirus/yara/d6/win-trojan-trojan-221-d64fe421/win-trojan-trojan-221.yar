rule Win_Trojan_Trojan_221
{
strings:
	$a0 = { 19002e810537314747e2f7 }


condition:
	$a0
}