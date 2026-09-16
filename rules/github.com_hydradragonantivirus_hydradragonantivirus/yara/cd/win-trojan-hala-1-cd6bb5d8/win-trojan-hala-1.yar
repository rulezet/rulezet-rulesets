rule Win_Trojan_Hala_1
{
strings:
	$a0 = { 558bec33c083ed0468 }

	$a1 = { 33c0640340308b400c8b701cad8b40088be8555b8bd303523c8b527803d58b5a2003dd33c0 }


condition:
	$a0 and $a1
}