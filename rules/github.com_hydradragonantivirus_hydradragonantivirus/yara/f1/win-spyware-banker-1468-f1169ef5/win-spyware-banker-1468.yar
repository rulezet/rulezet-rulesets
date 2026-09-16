rule Win_Spyware_Banker_1468
{
strings:
	$a0 = { 672ad978eda6198ac0165c004c6f8ec1e07ee8c72d53626dc4ee51b3eb3ea498c7a62059faf77acbc2ef62b5e43cd82aca19e8016ea677f23995a2e8392e5dc337627e4a }


condition:
	$a0
}