rule Win_Trojan_AST_1
{
strings:
	$a0 = { 2eff1e9801b4409c2eff1e9801b43e9c2eff1e9801c33d05ff7504b8ff05cf80fc4f75249c5053 }


condition:
	$a0
}