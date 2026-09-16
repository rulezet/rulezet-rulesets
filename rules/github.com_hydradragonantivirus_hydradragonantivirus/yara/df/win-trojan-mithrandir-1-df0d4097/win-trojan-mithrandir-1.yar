rule Win_Trojan_Mithrandir_1
{
strings:
	$a0 = { 35cd21891ebb028c06bd028cc8488ed8803e00005a752fa103002d3a007227832e03003a832e12003a8e061200bf }


condition:
	$a0
}