rule Win_Trojan_Camel_9
{
strings:
	$a0 = { cd2188d3b40bcd2180fc00750701eb2e3a0774531e06b44abbffffcd2181eb2600b8004a }


condition:
	$a0
}