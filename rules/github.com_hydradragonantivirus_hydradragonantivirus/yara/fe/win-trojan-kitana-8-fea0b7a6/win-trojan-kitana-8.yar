rule Win_Trojan_Kitana_8
{
strings:
	$a0 = { 41b703cd13381fc747fe55aab80203b70175f0c30e1fff0e1304cd12b179c1e0068ec033ff }


condition:
	$a0
}