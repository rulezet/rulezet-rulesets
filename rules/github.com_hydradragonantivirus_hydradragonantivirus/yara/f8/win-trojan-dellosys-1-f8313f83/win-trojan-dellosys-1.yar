rule Win_Trojan_Dellosys_1
{
strings:
	$a0 = { 0143ba2f01b92000cd21b8013dcd218bd8b103ba3901b440cd21b43ecd21ba2f01b80143b90700cd21b8004ccd21633a5c696f2e73797300494d4624 }


condition:
	$a0
}