rule Win_Trojan_Vriest_2
{
strings:
	$a0 = { b440b90005ba0001c70627020000cd21 }


condition:
	$a0
}