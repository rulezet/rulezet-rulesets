rule Win_Trojan_Small_4277
{
strings:
	$a0 = { 6a006a004975f9 }

	$a1 = { 0e000000726f6d647269766572732e }


condition:
	$a0 and $a1
}