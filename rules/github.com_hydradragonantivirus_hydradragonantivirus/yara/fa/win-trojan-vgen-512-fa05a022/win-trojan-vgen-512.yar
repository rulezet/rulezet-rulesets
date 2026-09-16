rule Win_Trojan_VGEN_512
{
strings:
	$a0 = { ee03bf0001fc501e065756b430cd2186e03d0a037251b8e033cd2180fca57447e877007205e8b300723d8cc0488e }


condition:
	$a0
}