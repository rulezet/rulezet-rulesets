rule Win_Trojan_SPS_4
{
strings:
	$a0 = { bf88aeb07f81ebb87480c5c4bf30019030c982f1aa22d22bd281c2e9e3909032ed82f507909020e431159797a7497f }


condition:
	$a0
}