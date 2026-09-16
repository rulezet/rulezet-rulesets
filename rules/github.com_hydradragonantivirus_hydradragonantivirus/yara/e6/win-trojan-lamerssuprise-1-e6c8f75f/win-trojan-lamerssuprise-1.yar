rule Win_Trojan_LamersSuprise_1
{
strings:
	$a0 = { 068b5408038c92008b9c940083ee3383ee2089440389 }


condition:
	$a0
}