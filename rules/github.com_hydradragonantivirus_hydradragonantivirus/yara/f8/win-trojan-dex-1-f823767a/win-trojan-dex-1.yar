rule Win_Trojan_Dex_1
{
strings:
	$a0 = { 33c98bd1cd2150b94c05b440cd2158c32ec606d000012e8b16da00e891ff3c007503b403c3 }


condition:
	$a0
}