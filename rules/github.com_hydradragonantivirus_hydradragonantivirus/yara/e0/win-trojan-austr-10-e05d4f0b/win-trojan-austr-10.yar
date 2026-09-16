rule Win_Trojan_Austr_10
{
strings:
	$a0 = { dd00cd21b800422bc92bd2cd21b440b103b601cd21 }


condition:
	$a0
}