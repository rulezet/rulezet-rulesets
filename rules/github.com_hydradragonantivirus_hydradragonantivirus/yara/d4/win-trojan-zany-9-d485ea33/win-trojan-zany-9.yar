rule Win_Trojan_Zany_9
{
strings:
	$a0 = { e800005d81ed0c01bf0001578db6da01a5a4b41a8d96e101cd21b44e8d96d10133c9cd21727bb8023d8d96ff01cd }


condition:
	$a0
}