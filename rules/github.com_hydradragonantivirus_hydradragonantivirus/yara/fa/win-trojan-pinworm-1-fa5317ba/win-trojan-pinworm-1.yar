rule Win_Trojan_Pinworm_1
{
strings:
	$a0 = { b8400350b90101ba0200cd13fec55850ebf8 }


condition:
	$a0
}