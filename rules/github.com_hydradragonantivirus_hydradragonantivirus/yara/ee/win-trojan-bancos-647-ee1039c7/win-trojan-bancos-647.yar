rule Win_Trojan_Bancos_647
{
strings:
	$a0 = { 8fcdeb0d588fe52455bc466374ed9e933b7314b6fd176b580a16b73fdfdffb9106c05b22975d7923fea883488228a9d9b9ec1fdbab568a6f2f73f595f9cbe17fafac905e }


condition:
	$a0
}