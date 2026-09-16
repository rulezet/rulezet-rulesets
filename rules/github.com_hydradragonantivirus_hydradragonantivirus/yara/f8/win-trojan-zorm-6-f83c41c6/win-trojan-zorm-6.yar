rule Win_Trojan_Zorm_6
{
strings:
	$a0 = { b91300488b1e1004cd11402bc393b0e702c32e8a2432e02e882446e2f5905696e9c62eee82e92b51fae85800000b1703e8 }


condition:
	$a0
}