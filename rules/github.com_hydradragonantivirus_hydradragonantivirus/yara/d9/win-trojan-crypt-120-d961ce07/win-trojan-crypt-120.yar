rule Win_Trojan_Crypt_120
{
strings:
	$a0 = { 59fec891803408??e2faffe0e8efffffffeb }


condition:
	$a0
}