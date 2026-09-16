rule Win_Trojan_Epsilon_2
{
strings:
	$a0 = { 7504b8f3f3cf603d004b7503e80600612eff2ebd02 }


condition:
	$a0
}