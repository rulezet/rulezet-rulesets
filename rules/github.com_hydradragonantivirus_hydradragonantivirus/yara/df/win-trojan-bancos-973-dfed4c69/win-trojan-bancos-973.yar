rule Win_Trojan_Bancos_973
{
strings:
	$a0 = { a28843e8f223e372fbfbf19ecf7c01926ac31a8594af75e0baf547a740fe405b31a97ffc53812988108adfe6c16752a65962a30d0d9fbbfe1c83a5c5e183a1b6 }


condition:
	$a0
}