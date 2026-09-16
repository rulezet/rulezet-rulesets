rule Win_Trojan_Toadie_4
{
strings:
	$a0 = { d5be410033ff4d8ec58eda4ab9080050ad352a2aabe2f9584879e68edd0e0733ffbe0700cb }


condition:
	$a0
}