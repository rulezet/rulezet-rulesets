rule Win_Trojan_Bauhaus_1
{
strings:
	$a0 = { 7a3bce04bb0301b8a6048b0eab04310f43433bd876f8c3e8eaff }


condition:
	$a0
}