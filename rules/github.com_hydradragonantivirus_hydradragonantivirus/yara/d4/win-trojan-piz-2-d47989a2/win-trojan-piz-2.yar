rule Win_Trojan_Piz_2
{
strings:
	$a0 = { eb019ae8a3001e5750eb01ea33c08ed8faff366c04b892032eff358f066c04eb01ea81366c }


condition:
	$a0
}