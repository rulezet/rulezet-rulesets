rule Win_Trojan_Grunt_7
{
strings:
	$a0 = { 408d9e4001483e8b96a80240b9930048 }


condition:
	$a0
}