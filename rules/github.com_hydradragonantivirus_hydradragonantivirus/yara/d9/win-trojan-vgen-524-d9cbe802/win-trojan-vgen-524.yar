rule Win_Trojan_VGEN_524
{
strings:
	$a0 = { 8bc205400050c32e9c589eb40972665abf00018bf283c609b90300f3a452b42fcd218bfa2e895d0c81c20002b41a }


condition:
	$a0
}