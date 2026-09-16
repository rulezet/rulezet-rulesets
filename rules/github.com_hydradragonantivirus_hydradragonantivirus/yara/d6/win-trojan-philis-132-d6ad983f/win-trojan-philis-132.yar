rule Win_Trojan_Philis_132
{
strings:
	$a0 = { 57565e545f5f81eb6b03c14581c36b03 }


condition:
	$a0
}