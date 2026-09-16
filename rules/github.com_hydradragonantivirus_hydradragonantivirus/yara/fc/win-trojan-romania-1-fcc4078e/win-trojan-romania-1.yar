rule Win_Trojan_Romania_1
{
strings:
	$a0 = { 8c062904b81325bac803cd210e1f8e062c0033ff }


condition:
	$a0
}