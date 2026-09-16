rule Win_Trojan_V472_1
{
strings:
	$a0 = { 31db8ec3bb8400268b0f890c46464343268b0f890cbe }


condition:
	$a0
}