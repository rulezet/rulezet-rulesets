rule Win_Trojan_EvilEmpireB_1
{
strings:
	$a0 = { c88ed88ec0bf0500b99a01fc8a0504 }


condition:
	$a0
}