rule Win_Trojan_Slop_1
{
strings:
	$a0 = { 0101b8fab88ec01f1e390686007436ff3684002e8f846d01ff3686002e8f846f018c1e84008c068600ff3640002e }


condition:
	$a0
}