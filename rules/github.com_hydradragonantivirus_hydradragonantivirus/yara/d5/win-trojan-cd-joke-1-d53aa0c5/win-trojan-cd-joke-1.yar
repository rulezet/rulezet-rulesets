rule Win_Trojan_CD_Joke_1
{
strings:
	$a0 = { 4f566950cd21663d2169554f0f85d6fc0668a8010e68030106685203cb }


condition:
	$a0
}