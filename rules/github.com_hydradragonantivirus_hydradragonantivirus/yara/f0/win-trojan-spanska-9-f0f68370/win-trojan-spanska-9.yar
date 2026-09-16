rule Win_Trojan_Spanska_9
{
strings:
	$a0 = { 6969cd2181fb69697503e9d00350558becc74602004a5d58bbffffcd2181eb150250558becc746 }


condition:
	$a0
}