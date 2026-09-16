rule Win_Trojan_VGEN_478
{
strings:
	$a0 = { e19d2e9ae24e73748664894d9624b44ccd21b42ccd2180fe107f2fb005a25a02b44eba5b02cd217221b8013dba9e }


condition:
	$a0
}