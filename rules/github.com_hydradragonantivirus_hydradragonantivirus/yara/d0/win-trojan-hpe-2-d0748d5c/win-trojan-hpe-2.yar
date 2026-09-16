rule Win_Trojan_HPE_2
{
strings:
	$a0 = { 9835faf0c2f2e77987e3481a7df6c5d90751b0f87cb27387c03fead4459fd8f499fcc84cd0f36e97 }


condition:
	$a0
}