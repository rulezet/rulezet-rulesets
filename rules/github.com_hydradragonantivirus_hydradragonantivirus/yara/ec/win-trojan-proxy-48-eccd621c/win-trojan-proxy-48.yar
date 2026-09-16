rule Win_Trojan_Proxy_48
{
strings:
	$a0 = { 83caff425252beb8174900ff1609c0752e89c281c2cbac49f081c23565ff0f8d8a3cf5ffff81c1001000005205f0dfafb12902832a0f31c08d520439ca7eedbed6174900ff16c3 }


condition:
	$a0
}