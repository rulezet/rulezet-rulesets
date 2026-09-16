rule Win_Trojan_Bootache_3
{
strings:
	$a0 = { 0409b9e53782c5d0b00a2e0005d2c847e2f889fb81ebfc089148fce82905e90000cd210ac474611e8bcb8cdfb413cd }


condition:
	$a0
}