rule Win_Trojan_SillyC_93
{
strings:
	$a0 = { fa4f16742ab43fe84d00b002e85000a3ba01b440e84000720eb000e84100b4408d160001e83300 }


condition:
	$a0
}