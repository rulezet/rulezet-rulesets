rule Win_Trojan_Wizard_2
{
strings:
	$a0 = { c0bf000226813de800740fb90c01f3a4061fba4502 }


condition:
	$a0
}