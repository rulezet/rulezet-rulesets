rule Win_Trojan_Piz_3
{
strings:
	$a0 = { eb019ae8a9001e5750eb01ea33c08ed8faff366c04c7060c0095032eff358f066c04eb01ea81 }


condition:
	$a0
}