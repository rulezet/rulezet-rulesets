rule Win_Trojan_Gen_156
{
strings:
	$a0 = { 2a2e455845042e4f564c5589e5b800019acd02690081ec0001bf3b030e57b83f0050bf5200 }


condition:
	$a0
}