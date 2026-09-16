rule Win_Trojan_Orudis_1
{
strings:
	$a0 = { b9c2038db647018bfeac2e32a61c05aae2f7c3 }


condition:
	$a0
}