rule Win_Trojan_ItaVir_4
{
strings:
	$a0 = { 8a16d70b80fa02741b1e52b41ccd218a075a }


condition:
	$a0
}