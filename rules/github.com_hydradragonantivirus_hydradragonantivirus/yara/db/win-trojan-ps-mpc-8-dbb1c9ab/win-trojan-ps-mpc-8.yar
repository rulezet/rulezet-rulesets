rule Win_Trojan_PS_MPC_8
{
strings:
	$a0 = { a5c6865003008d96d502e86b008d96db02e8640080 }


condition:
	$a0
}