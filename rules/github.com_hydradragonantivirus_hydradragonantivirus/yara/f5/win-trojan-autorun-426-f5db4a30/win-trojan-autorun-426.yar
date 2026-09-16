rule Win_Trojan_Autorun_426
{
strings:
	$a0 = { 225b6175746f72756e5d }

	$a1 = { 7368656c6c657865637574653d777363726970742e65786520 }

	$a2 = { 2e766273 }


condition:
	$a0 and $a1 and $a2
}