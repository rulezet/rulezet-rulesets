rule Win_Trojan_Morose_1
{
strings:
	$a0 = { 804d5c30c9dcdbc327ee1d531d65e8dcde18ef14fb7eddddfb51d3dfdd2b2c3602 }


condition:
	$a0
}