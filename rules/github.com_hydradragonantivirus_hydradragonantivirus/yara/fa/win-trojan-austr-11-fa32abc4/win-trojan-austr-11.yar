rule Win_Trojan_Austr_11
{
strings:
	$a0 = { b9e500cd21b800422bc92bd2cd21b440b103b601cd21 }


condition:
	$a0
}