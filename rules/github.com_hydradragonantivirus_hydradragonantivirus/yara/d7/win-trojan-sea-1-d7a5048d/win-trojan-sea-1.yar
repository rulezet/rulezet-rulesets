rule Win_Trojan_Sea_1
{
strings:
	$a0 = { 0102998edabc007c8ed28bdc8ec0b90100b280cd13721b26813ffcb87414b80103b10550cd13 }


condition:
	$a0
}