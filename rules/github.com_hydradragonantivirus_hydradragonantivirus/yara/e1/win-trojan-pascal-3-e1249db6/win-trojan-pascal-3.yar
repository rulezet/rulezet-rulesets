rule Win_Trojan_Pascal_3
{
strings:
	$a0 = { 21e800005e81ee6501888454018b8406 }


condition:
	$a0
}