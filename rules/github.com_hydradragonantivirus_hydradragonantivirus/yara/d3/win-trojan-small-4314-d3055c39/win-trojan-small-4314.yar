rule Win_Trojan_Small_4314
{
strings:
	$a0 = { 60e8540000005050e836000000e87a0000008d2dbd797326e85700000052ffd2 }


condition:
	$a0
}