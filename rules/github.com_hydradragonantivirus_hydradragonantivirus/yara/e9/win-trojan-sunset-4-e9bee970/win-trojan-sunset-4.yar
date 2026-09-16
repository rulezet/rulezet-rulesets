rule Win_Trojan_Sunset_4
{
strings:
	$a0 = { 6a005589e5b8000b9a7c026a0081ec000b9a8b0c6a00bf62020e579ae90c6a009a3f026a0009c07503e84afebf }


condition:
	$a0
}