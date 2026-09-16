rule Win_Trojan_Fist_6
{
strings:
	$a0 = { 02e881695daf38bc5378b40138694bb9f4a383736d7b459f0683aa0c184e88a70615478d024cdb1f4912ba9696 }


condition:
	$a0
}