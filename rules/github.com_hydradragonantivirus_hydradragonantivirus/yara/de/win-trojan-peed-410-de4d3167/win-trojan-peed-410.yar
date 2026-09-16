rule Win_Trojan_Peed_410
{
strings:
	$a0 = { 8b150003fe7f81fa00a000007f03f8abc3b983bf }


condition:
	$a0
}