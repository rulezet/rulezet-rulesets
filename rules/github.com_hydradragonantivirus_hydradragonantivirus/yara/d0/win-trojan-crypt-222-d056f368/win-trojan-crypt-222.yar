rule Win_Trojan_Crypt_222
{
strings:
	$a0 = { 68fc6c4300e8b45002006893194300e8605302 }

	$a1 = { 4300200d2d484b657900d508486c6f }


condition:
	$a0 and $a1
}