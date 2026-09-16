rule Win_Trojan_Jerusalem_8
{
strings:
	$a0 = { b97250ba746fcd0981fe532e754a81ff5359754426 }


condition:
	$a0
}