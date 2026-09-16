rule Win_Trojan_VGEN_467
{
strings:
	$a0 = { c08ec0baaaaa2689161604d1cab90101b405cd16b410cd16cd05b8070a32ffb90100cd10b486 }


condition:
	$a0
}