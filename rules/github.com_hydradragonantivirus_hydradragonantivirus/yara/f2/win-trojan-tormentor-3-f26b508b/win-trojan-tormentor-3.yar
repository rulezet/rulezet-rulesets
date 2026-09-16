rule Win_Trojan_Tormentor_3
{
strings:
	$a0 = { ead1d8e2fa8bd7c3b440b91004ba0001e80a00eb01909c }


condition:
	$a0
}