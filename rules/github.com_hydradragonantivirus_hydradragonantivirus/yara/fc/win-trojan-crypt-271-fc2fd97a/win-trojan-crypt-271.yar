rule Win_Trojan_Crypt_271
{
strings:
	$a0 = { 9090909053909057569090e898fdffff909090906a00909090e8caffffff9083 }


condition:
	$a0
}