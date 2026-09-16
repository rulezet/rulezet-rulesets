rule Win_Trojan_Crypt_143
{
strings:
	$a0 = { 81c0????????(01|29|31)(01|02|03|06|07)81e8[0-20]3b(c8|d0|d8|e8|f0|f8)0f82??ffffff }


condition:
	$a0
}