rule Win_Trojan_Rebel_1
{
strings:
	$a0 = { 8b1e0b00ba6600b920009c2eff1e9400c3900e078bdabf0d008a27268825434780fc0075f40e }


condition:
	$a0
}