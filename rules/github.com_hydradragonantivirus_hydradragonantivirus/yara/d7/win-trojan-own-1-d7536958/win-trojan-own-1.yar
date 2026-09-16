rule Win_Trojan_Own_1
{
strings:
	$a0 = { 6f6e222c226d757374646965 }

	$a1 = { 776e6572222c226c616d6572 }

	$a2 = { 7a6174696f6e222c226d6963726f7c737578 }


condition:
	$a0 and $a1 and $a2
}