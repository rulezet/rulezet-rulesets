rule Win_Trojan_Bancos_928
{
strings:
	$a0 = { a99c94dd054214e09d642f51551bfe129deef988fea8aba898a7ca09472198ec6de09d12e8aaf1c484ae4c50df63da75fe2a304d1b410a3c13fd17ab2b94ea3755fd19ecd4f70ba8a63a67b9ff15bed89fea }


condition:
	$a0
}