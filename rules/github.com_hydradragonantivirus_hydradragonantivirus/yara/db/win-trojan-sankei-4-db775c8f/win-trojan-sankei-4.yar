rule Win_Trojan_Sankei_4
{
strings:
	$a0 = { e8000000005d81ed051040008db528104000b98805000056 }


condition:
	$a0
}