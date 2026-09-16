rule Win_Trojan_Kampi_1
{
strings:
	$a0 = { b8ffffcd21[0-1]0e1f8ec0bf00018bf5b9e803f3a61f077504 }


condition:
	$a0
}