rule Win_Trojan_Crypt_134
{
strings:
	$a0 = { 81c2????????e8??000000[0-50]0fb701[0-10]66353412[0-10]663d }


condition:
	$a0
}