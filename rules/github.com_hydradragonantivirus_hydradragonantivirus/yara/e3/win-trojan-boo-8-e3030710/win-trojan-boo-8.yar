rule Win_Trojan_BOO_8
{
strings:
	$a0 = { ba7100ec0c80ee07be4c00bf2b01fca5a58c44fec744fc3101b404cd1a81fa04097539b406 }


condition:
	$a0
}