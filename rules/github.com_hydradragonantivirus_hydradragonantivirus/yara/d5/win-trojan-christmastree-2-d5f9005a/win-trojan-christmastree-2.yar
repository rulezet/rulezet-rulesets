rule Win_Trojan_ChristmasTree_2
{
strings:
	$a0 = { 2181fa130c730881fa01017202eb0e }


condition:
	$a0
}