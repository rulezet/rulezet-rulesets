rule Win_Trojan_Autorun_157
{
strings:
	$a0 = { 8a038bd080c2d080ea0a72e085ff7d02f7de33c05a595964891068b7424000c3 }


condition:
	$a0
}