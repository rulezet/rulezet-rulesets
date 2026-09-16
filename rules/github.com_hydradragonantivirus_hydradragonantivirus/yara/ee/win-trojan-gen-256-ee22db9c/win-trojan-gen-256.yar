rule Win_Trojan_Gen_256
{
strings:
	$a0 = { 8e005589e5b802029a7c028e0081ec0202bf4c2a1e57bf4e2a1e57bf502a1e57bf522a1e579a00005f00833e52 }


condition:
	$a0
}