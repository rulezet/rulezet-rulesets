rule Win_Trojan_Jesus_1
{
strings:
	$a0 = { b2cf23ff902e2894217ba6e2f7b7cfcf2d52bdd55a53dfcfbad1cfcf881ed15c8bf1cfbacf00d45296d1b1c8 }


condition:
	$a0
}