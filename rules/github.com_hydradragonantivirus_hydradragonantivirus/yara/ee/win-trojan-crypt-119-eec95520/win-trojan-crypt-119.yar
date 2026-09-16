rule Win_Trojan_Crypt_119
{
strings:
	$a0 = { 59fec891803408??e2fa50c3e8efffffffeb }


condition:
	$a0
}