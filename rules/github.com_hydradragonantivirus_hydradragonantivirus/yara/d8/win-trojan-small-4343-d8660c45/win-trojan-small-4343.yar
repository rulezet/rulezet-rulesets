rule Win_Trojan_Small_4343
{
strings:
	$a0 = { 89c689c789c381c000bcbffff7d85050e82300000029c05050 }


condition:
	$a0
}