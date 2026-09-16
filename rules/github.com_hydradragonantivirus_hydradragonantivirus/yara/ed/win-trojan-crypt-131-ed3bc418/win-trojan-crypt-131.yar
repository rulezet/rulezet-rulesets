rule Win_Trojan_Crypt_131
{
strings:
	$a0 = { 8124240000ffff[0-30]668139[0-20]81e900100000[0-50]8cc9 }


condition:
	$a0
}