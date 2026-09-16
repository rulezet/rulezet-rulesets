rule Win_Trojan_Bleah_1
{
strings:
	$a0 = { ffbb1304be007cfa8ed78be68edfa122003d00f07525a3047ca12000a3027c8b07a30a7cc6077e }


condition:
	$a0
}