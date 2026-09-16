rule Win_Trojan_SST_10
{
strings:
	$a0 = { 6578740d0a456e642046756e6374696f6e0d0a27566273776720312e353062 }


condition:
	$a0
}