rule Win_Trojan_Autorun_446
{
strings:
	$a0 = { 5b6175746f72756e5d206f70656e3d62696e5c72656379636c655c62696e2e657865 }


condition:
	$a0
}