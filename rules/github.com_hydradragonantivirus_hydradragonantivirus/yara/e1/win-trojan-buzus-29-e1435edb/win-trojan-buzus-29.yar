rule Win_Trojan_Buzus_29
{
strings:
	$a0 = { e88f320000e916feffff5064ff35000000008d44240c2b64240c53565789288b }


condition:
	$a0
}