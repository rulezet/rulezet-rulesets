rule Win_Trojan_Peed_32
{
strings:
	$a0 = { 89c381c32c4d40006a4281c3ff23511fff9301dcaee0b894dcef0152682ae1af }


condition:
	$a0
}