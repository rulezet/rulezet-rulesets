rule Win_Trojan_Swisyn_6
{
strings:
	$a0 = { 554e4b4f574e }

	$a1 = { 69616c6d726e74342e646c6c }


condition:
	$a0 and $a1
}