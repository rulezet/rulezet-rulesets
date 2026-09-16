rule Win_Trojan_Trojan_153
{
strings:
	$a0 = { e9000050b9f70f8b1e010181c3150180370043e2fa }


condition:
	$a0
}