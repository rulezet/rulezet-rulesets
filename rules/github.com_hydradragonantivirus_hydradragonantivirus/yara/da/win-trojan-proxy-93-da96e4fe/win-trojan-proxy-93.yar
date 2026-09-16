rule Win_Trojan_Proxy_93
{
strings:
	$a0 = { c3b5975f77083a9fdff35912b6316d72 }


condition:
	$a0
}