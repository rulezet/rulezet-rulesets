rule Win_Trojan_Philis_85
{
strings:
	$a0 = { e8ddbbffffe8acfbffffc605d4f1410000c605d7f14100008d45fc506a006a00689cee40006a006a00e86cb2ffffc605d5f1410001a10c124100f6401c0174276830750000e8e8b3ffff }


condition:
	$a0
}