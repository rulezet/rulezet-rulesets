rule Win_Trojan_Tiny_83
{
strings:
	$a0 = { 69b04df2ae7418b002e81d00b186cd69 }


condition:
	$a0
}