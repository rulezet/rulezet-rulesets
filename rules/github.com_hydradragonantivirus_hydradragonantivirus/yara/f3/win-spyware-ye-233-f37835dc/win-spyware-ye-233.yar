rule Win_Spyware_ye_233
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]e634f0c501a0cbfda7d4ffe9892e66 }


condition:
	$a0
}