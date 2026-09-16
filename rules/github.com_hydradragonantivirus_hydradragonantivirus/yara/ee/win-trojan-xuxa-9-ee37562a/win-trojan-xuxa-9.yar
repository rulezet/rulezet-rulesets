rule Win_Trojan_Xuxa_9
{
strings:
	$a0 = { 2e01bf0001be8506b900ff81e98506b4ddcd21eb27 }


condition:
	$a0
}