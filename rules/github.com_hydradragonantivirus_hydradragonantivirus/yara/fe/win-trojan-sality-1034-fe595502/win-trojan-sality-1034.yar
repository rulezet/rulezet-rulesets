rule Win_Trojan_Sality_1034
{
strings:
	$a0 = { 6003d0fecaeb019c8bf56a00ff1504100001e8000000002bd6ffc6f30fb7d95881c0e0 }


condition:
	$a0
}