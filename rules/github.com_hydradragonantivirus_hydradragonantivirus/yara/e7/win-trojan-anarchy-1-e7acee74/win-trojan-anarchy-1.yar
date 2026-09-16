rule Win_Trojan_Anarchy_1
{
strings:
	$a0 = { e2f455f11a18525ef01818461f1e079bf67f4ea0180ad537e224e76a11f03412e2f022196a4a061f4593 }


condition:
	$a0
}