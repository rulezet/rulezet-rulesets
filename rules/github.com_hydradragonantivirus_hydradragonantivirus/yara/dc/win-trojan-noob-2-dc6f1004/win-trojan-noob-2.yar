rule Win_Trojan_Noob_2
{
strings:
	$a0 = { 31352073746172666972657a }

	$a1 = { 6f6e20313a6a6f696e3a233a7b206966 }

	$a2 = { 286e6f6861636b206973696e20246368616e }

	$a3 = { 7669726969 }


condition:
	$a0 and $a1 and $a2 and $a3
}