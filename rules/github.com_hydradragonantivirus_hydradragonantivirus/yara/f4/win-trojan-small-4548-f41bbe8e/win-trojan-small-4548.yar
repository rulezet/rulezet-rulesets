rule Win_Trojan_Small_4548
{
strings:
	$a0 = { 89c581c5????4200be????4200adffd001d5e83800000050e82400000055e837000000 }


condition:
	$a0
}