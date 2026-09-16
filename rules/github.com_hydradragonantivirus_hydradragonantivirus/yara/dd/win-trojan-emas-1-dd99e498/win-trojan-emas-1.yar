rule Win_Trojan_Emas_1
{
strings:
	$a0 = { 2135cd211f891eb2098c06b409ba9402b82125cd21 }


condition:
	$a0
}