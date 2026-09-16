rule Win_Trojan_Trojan_216
{
strings:
	$a0 = { 0300cd2000ba4559b801facd211e06e800005d81ed13018d969202b41acd213ec686750200e82400071f }


condition:
	$a0
}