rule Win_Trojan_V_28
{
strings:
	$a0 = { 26a113044848503d000172032d3e }


condition:
	$a0
}