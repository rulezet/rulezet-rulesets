rule Win_Trojan_CVME_2
{
strings:
	$a0 = { 161f8db60001fcf3a4061fe83500161fb80043cd2f3c80750fb81043cd2f06538bf4ff1c585807 }


condition:
	$a0
}