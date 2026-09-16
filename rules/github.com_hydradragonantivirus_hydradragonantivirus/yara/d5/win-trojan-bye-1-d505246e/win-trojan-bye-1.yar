rule Win_Trojan_Bye_1
{
strings:
	$a0 = { 0e008bf0fcbf0001b90300f3a4061e50b4fecd213d3cc35875071f07be000156c38cdb4b8ec326803e00005a75ec }


condition:
	$a0
}