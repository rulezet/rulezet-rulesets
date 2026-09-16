rule Win_Trojan_Austr_7
{
strings:
	$a0 = { d5cd21b800422bc92bd2cd21b440b103b601cd215a }


condition:
	$a0
}