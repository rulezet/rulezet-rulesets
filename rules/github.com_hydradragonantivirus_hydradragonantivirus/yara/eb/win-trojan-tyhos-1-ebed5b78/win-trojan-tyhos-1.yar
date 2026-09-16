rule Win_Trojan_Tyhos_1
{
strings:
	$a0 = { 6e65742d67686f7a7479 }

	$a1 = { 696f6e5c52756e0061767075706474 }

	$a2 = { 4f70656e002d66616b65 }


condition:
	$a0 and $a1 and $a2
}