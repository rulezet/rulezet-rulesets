rule Win_Trojan_Hupigon_696
{
strings:
	$a0 = { 7193e310394facf62b54e04957db36fd782c30d2318edade42d10640a7ea32d648a30b8a0f9b6b285009926f2b2bfa7d10c5b207c4294c78b5d2929d }


condition:
	$a0
}