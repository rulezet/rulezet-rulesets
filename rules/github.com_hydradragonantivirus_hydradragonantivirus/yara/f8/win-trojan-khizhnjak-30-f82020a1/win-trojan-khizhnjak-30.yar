rule Win_Trojan_Khizhnjak_30
{
strings:
	$a0 = { 2e8a879e008887dc022e80bf9e000074094383fb0d }


condition:
	$a0
}