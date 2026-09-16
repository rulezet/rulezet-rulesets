rule Win_Trojan_Bobas_1
{
strings:
	$a0 = { 0680fcfe750f81fb52537403e92801071f618bc3cf80fc }


condition:
	$a0
}