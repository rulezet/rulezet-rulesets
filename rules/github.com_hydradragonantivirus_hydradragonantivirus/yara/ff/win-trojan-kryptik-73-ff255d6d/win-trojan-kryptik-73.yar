rule Win_Trojan_Kryptik_73
{
strings:
	$a0 = { 653a5c676f6f676c655c7372635c5f7469676572345f76335f322e706462 }


condition:
	$a0
}