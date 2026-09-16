rule Win_Trojan_Minsk_1
{
strings:
	$a0 = { c831dbcd2183fbff7503e91e011e5b4bfa8edba10300 }


condition:
	$a0
}