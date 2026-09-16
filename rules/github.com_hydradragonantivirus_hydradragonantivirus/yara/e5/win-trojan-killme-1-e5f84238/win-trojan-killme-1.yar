rule Win_Trojan_Killme_1
{
strings:
	$a0 = { 83c620905681c643008ccbb9ed062e8a0432c42e880446e2f55ee9fe05 }


condition:
	$a0
}