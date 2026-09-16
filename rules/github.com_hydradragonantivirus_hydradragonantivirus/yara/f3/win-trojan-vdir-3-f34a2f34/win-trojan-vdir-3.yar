rule Win_Trojan_Vdir_3
{
strings:
	$a0 = { c704a5a5c74402a5a5b8013ebbadfecd2181f3adde7511 }


condition:
	$a0
}