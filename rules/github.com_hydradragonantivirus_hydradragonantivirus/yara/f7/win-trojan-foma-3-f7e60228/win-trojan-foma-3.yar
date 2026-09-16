rule Win_Trojan_Foma_3
{
strings:
	$a0 = { 4004e8e5fc0e1f897512c7451a0001c74508b0fec685f802008bf7fa0633c08ed8bb0400c43f26ff352e8f441e26 }


condition:
	$a0
}