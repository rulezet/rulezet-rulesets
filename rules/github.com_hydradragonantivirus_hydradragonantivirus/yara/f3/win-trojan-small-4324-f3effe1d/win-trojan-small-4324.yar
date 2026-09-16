rule Win_Trojan_Small_4324
{
strings:
	$a0 = { 60e8540000005050e836000000e87a0000008d2dbdf97226 }


condition:
	$a0
}