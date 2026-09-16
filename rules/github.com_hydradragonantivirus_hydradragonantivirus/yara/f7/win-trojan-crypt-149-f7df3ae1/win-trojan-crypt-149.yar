rule Win_Trojan_Crypt_149
{
strings:
	$a0 = { 81c7????????(01|29|31)(39|39|3a|3b|3e)81ef[0-20]3b(c7|cf|d7|df|ee|f7)0f82??ffffff }


condition:
	$a0
}