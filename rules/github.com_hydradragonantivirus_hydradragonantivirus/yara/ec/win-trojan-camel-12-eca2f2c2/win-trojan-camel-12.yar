rule Win_Trojan_Camel_12
{
strings:
	$a0 = { e800005d83ed }

	$a1 = { 8d76??89f7b9e800ad7304abe2fac3 }


condition:
	$a0 and $a1
}