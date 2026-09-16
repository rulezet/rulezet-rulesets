rule Win_Trojan_Diamond_9
{
strings:
	$a0 = { ffb927008b55022bd13bd0723a26294d038955 }


condition:
	$a0
}