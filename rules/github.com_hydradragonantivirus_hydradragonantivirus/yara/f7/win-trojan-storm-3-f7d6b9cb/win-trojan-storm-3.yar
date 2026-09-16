rule Win_Trojan_Storm_3
{
strings:
	$a0 = { 3d004b74143dfe4b907507bd3412909dfbcffb9d2eff }


condition:
	$a0
}