rule Win_Trojan_Gen_20
{
strings:
	$a0 = { 3ceb7403e983fe0e07acac2ae403f08bfe8d36d703b98600f3a42bd2b9010032c08d1eec0fcd26 }


condition:
	$a0
}