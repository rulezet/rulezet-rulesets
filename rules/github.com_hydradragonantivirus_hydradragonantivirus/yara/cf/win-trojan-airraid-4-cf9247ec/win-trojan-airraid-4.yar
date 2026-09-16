rule Win_Trojan_AirRaid_4
{
strings:
	$a0 = { 9b8b16e697b96303d3d2cc0bd3bee570bf9bb2bbf153b2e0b461cd2136299c4a91fc26299c4a919f3e319c4a912b }


condition:
	$a0
}