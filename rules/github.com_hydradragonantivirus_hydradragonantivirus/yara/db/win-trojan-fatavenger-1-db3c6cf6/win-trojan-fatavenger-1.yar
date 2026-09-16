rule Win_Trojan_FatAvenger_1
{
strings:
	$a0 = { 1bfbbe13048b042d03008904bb4000f7e38ec0bb0001b80402be007c8b54268a6c28b103cd13 }


condition:
	$a0
}