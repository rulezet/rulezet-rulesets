rule Win_Trojan_Vova_1
{
strings:
	$a0 = { ce8a84ff042a06fa048884ff04e2f089d1ba0000be0000b8cd19a33201eb00b80000e9c103 }


condition:
	$a0
}