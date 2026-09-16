rule Win_Trojan_VGEN_207
{
strings:
	$a0 = { 018bf5e8ab00b409ba1401cd21b8004ccd2146524f444f204c495645532124e800005d83ed0355e838005d2e807e }


condition:
	$a0
}