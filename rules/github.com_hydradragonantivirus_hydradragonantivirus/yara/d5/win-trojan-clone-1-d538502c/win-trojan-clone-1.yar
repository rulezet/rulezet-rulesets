rule Win_Trojan_Clone_1
{
strings:
	$a0 = { 2acd2180fe04750c80fa017507bad803b409cd21b800dacd2181fbff117503eb4890fa8cc88ed0bc4106fbbb8000b4 }


condition:
	$a0
}