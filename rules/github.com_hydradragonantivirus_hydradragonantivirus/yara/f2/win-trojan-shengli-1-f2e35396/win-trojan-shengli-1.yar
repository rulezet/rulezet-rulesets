rule Win_Trojan_Shengli_1
{
strings:
	$a0 = { b91800b440cd2133c98bd1b80242cd2133d2b90004b440cd215ab43ecd218b0e0804b80143 }


condition:
	$a0
}