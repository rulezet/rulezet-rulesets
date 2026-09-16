rule Win_Trojan_Kit_3
{
strings:
	$a0 = { 1900b82425cd21071f5f5e5a595b589d2eff2e1100 }


condition:
	$a0
}