rule Win_Trojan_Eddy_1
{
strings:
	$a0 = { b40f86e090cd213d01017434b8213590cd2126813e0a }


condition:
	$a0
}