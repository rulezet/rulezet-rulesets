rule Win_Trojan_BR_2
{
strings:
	$a0 = { 5e81ee4301fa33c08ed88ed0bc007ca113042d0200a31304b106d3e08ec02e89847501bf00 }


condition:
	$a0
}