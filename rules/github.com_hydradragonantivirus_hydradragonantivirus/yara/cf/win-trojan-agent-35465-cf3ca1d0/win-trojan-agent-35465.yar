rule Win_Trojan_Agent_35465
{
strings:
	$a0 = { b8b0955c005064ff35000000006489250000000033c0 }


condition:
	$a0
}