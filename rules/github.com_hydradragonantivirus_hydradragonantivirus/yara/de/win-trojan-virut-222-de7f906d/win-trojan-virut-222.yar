rule Win_Trojan_Virut_222
{
strings:
	$a0 = { f5e81e0000005dc3b70053b9d20f00008bda66311083e8ff86d683e8ff8d1413e2f05bc385c07513cd2ec1e01f792483 }


condition:
	$a0
}