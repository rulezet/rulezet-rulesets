rule Win_Trojan_Horror_3
{
strings:
	$a0 = { 83c70ab944042e8a8493042e3005fec047e2f8c3 }


condition:
	$a0
}