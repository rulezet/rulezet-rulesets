rule Win_Trojan_VGEN_281
{
strings:
	$a0 = { 4e8bfe81c600ffba5601b15ccd217235ba9e00b8023dcd2193b6feb43fcd21803e9efeb47417b002e81e00a30601b4 }


condition:
	$a0
}