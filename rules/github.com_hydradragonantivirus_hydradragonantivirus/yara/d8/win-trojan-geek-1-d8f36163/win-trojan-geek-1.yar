rule Win_Trojan_Geek_1
{
strings:
	$a0 = { 4b7403e90c01505351521eb80043cd215133c9b80143 }


condition:
	$a0
}