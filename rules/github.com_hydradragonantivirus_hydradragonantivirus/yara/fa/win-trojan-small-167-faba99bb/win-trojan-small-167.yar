rule Win_Trojan_Small_167
{
strings:
	$a0 = { b82135cd21891eb7018c06b9016a6007b9c8005126803e00002f7410be000133fff3a4061fb425ba4d00cd210e1fa1 }


condition:
	$a0
}