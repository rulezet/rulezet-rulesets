rule Win_Trojan_Beijing_1
{
strings:
	$a0 = { 03be0300b82135cd21bf0c0103fe2e89 }


condition:
	$a0
}