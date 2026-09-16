rule Win_Trojan_Id_31
{
strings:
	$a0 = { 3c3f706870202f2a207a66786964202a2f }

	$a1 = { 2f2a207a66786964202a2f203f3e }


condition:
	$a0 and $a1
}