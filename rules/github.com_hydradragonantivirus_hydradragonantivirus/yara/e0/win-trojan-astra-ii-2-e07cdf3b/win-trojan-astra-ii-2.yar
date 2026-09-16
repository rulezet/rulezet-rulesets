rule Win_Trojan_Astra_II_2
{
strings:
	$a0 = { 5d81ed0300e8c601bf894337c8c3c2f0da36fa3543c5e78e62038e17c8c36dbac7f94218caaa8e376dbac7cd42 }


condition:
	$a0
}