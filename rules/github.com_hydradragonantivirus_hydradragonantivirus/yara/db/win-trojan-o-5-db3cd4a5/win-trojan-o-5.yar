rule Win_Trojan_O_5
{
strings:
	$a0 = { 8a84e801b9e801f6d82e300446e2f8c3 }


condition:
	$a0
}