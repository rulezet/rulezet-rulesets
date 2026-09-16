rule Win_Trojan_Small_4237
{
strings:
	$a0 = { 400053535f5d81c79c070000be5e }


condition:
	$a0
}