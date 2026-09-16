rule Win_Trojan_USSR_17
{
strings:
	$a0 = { c8ba2a02b440cd217248b440b9ec01ba0001cd21 }


condition:
	$a0
}