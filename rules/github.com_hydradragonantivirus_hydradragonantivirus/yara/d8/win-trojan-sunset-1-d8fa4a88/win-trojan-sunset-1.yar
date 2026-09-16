rule Win_Trojan_Sunset_1
{
strings:
	$a0 = { cd218beb066a000726c606ac03ea8bc383c32d051a0426a3ad03268c0eaf0307536a0068ac03cb }


condition:
	$a0
}