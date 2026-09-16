rule Win_Trojan_SillyOR_7
{
strings:
	$a0 = { 2135cd21891e46018c064801ba4501b83225cd21ba2101b021cd32ba4b01cd2780fc3e751f1e52515033c933d2b800 }


condition:
	$a0
}