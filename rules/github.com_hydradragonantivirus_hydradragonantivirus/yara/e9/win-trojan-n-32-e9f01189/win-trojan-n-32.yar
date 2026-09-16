rule Win_Trojan_N_32
{
strings:
	$a0 = { 8bfc368b2d81ed0c012e803e5e01b9744fb9b2058dbe5e01ba01008105cd49802dd88035d3 }


condition:
	$a0
}