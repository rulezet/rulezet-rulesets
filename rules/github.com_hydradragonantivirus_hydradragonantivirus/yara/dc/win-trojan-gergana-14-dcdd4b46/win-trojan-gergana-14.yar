rule Win_Trojan_Gergana_14
{
strings:
	$a0 = { b43fcd21c3b90002b440cd21c3b801572e8b0e5001 }


condition:
	$a0
}