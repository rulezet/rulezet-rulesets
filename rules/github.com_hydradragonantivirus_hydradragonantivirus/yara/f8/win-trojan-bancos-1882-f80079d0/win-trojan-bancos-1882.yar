rule Win_Trojan_Bancos_1882
{
strings:
	$a0 = { 0d8b84372ba2aab4b7e1d01823c76377e884934eece1c4ac61e3e3e5509472ed9cc487c862cd24e2eef435d0b0302609baf0f2579977ae20550490fbae61dcc26f44ebf44336 }


condition:
	$a0
}