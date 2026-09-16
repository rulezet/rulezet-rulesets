rule Win_Trojan_Delf_1515
{
strings:
	$a0 = { 558bec83c4f0b8e0db4400e84089fbff68d8dd44006aff6a00e8868afbffe8318bfbff3db70000007505e8c564fbff }


condition:
	$a0
}