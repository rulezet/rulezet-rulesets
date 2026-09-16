rule Win_Trojan_Simbioz_3
{
strings:
	$a0 = { 4033d2cd217219b8024233c933d2cd21720eb440b92201900e1f8bd5cd217200b801572e8b0ef4 }


condition:
	$a0
}