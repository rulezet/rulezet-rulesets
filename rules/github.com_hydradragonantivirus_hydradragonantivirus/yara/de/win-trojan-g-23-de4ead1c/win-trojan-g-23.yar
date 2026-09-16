rule Win_Trojan_G_23
{
strings:
	$a0 = { 04eb7413803e0004007738e85a00b403b702e889ff7207b403b700e83a00 }


condition:
	$a0
}