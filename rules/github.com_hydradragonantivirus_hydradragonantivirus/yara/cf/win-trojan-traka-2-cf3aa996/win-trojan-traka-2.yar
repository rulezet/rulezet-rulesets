rule Win_Trojan_Traka_2
{
strings:
	$a0 = { 5053515756e800005d81ed0900b87c0003c5ffd0be0301ad3d54547521bf0001be3a0003f5a5a5a45e5f595b585d53 }


condition:
	$a0
}