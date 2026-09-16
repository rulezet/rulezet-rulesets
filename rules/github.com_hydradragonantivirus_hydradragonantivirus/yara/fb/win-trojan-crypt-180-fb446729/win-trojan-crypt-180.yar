rule Win_Trojan_Crypt_180
{
strings:
	$a0 = { b80d204c002d76960b00488b088b50040fca0fc98915a2d04100890d9ed041008b48088b500c0fca0fc989 }


condition:
	$a0
}