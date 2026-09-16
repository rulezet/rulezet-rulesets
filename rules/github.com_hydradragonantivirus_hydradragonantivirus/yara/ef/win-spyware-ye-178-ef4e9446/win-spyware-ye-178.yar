rule Win_Spyware_ye_178
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]af7db90ecae99ccef09dc02a4a6f27 }


condition:
	$a0
}