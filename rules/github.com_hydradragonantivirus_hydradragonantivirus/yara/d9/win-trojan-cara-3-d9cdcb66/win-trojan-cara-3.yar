rule Win_Trojan_Cara_3
{
strings:
	$a0 = { 1fc606b2020190e84f00b86221e85d00b86320 }


condition:
	$a0
}