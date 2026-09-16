rule Win_Trojan_Lapidario_1
{
strings:
	$a0 = { 04b02aeb02b0023e8886f7038d8ec3038d8610018bf02bc83e8aa6ff038bfeac02c4aae2fa }


condition:
	$a0
}