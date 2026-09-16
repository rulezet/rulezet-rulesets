rule Win_Trojan_Smurf_2
{
strings:
	$a0 = { d1f5803e9e0103751ebfa2001e57bfcf0a0e579a8d097001bfa2001e57bfde0a0e579a550b7001e88bf3bfba021e57 }


condition:
	$a0
}