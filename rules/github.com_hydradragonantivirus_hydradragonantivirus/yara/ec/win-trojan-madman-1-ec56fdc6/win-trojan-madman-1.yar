rule Win_Trojan_MadMan_1
{
strings:
	$a0 = { 76438f7bf5451713177cff3827413542374f35f7fae5883d3241334b22f386f366441f599c17cb76 }


condition:
	$a0
}