rule Win_Trojan_CarryOn_1
{
strings:
	$a0 = { 8100bf89022e033e0101b97f00fcf3a4fe4600b42acd2181fa16097337b44e33c9ba96012e03160101cd217230bd9c }


condition:
	$a0
}