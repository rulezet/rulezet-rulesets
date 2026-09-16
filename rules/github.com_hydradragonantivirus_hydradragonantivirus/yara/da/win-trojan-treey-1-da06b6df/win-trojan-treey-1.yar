rule Win_Trojan_Treey_1
{
strings:
	$a0 = { 04e9a18f0405eb01a36604ba6504b90300b440cd218b0e8b048b168d04b80157cd21b43ecd }


condition:
	$a0
}