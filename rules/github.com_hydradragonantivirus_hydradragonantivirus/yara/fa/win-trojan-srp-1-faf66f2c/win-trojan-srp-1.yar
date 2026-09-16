rule Win_Trojan_Srp_1
{
strings:
	$a0 = { fe83c4066a2168c008e8b10583c4040bc0750f8d46ea50e8f80259e8da050bc074f1ff76feff }


condition:
	$a0
}